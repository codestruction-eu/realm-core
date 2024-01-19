////////////////////////////////////////////////////////////////////////////
//
// Copyright 2015 Realm Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////

#include <realm/object-store/impl/transact_log_handler.hpp>

#include <realm/object-store/binding_context.hpp>
#include <realm/object-store/impl/collection_notifier.hpp>
#include <realm/object-store/index_set.hpp>
#include <realm/object-store/shared_realm.hpp>

#include <realm/db.hpp>

#include <algorithm>
#include <numeric>

using namespace realm;

namespace {

class KVOAdapter : public _impl::TransactionChangeInfo {
public:
    KVOAdapter(std::vector<BindingContext::ObserverState>& observers, BindingContext* context, bool is_rollback);

    void before(Transaction& sg);
    void after(Transaction& sg);

private:
    BindingContext* m_context;
    std::vector<BindingContext::ObserverState>& m_observers;
    std::vector<void*> m_invalidated;

    struct ListInfo {
        BindingContext::ObserverState* observer;
        _impl::CollectionChangeBuilder builder;
        ColKey col_key;
    };
    std::vector<ListInfo> m_lists;
    VersionID m_version;
    bool m_rollback;
};

KVOAdapter::KVOAdapter(std::vector<BindingContext::ObserverState>& observers, BindingContext* context,
                       bool is_rollback)
    : _impl::TransactionChangeInfo{}
    , m_context(context)
    , m_observers(observers)
    , m_rollback(is_rollback)
{
    if (m_observers.empty())
        return;

    std::vector<TableKey> tables_needed;
    for (auto& observer : observers) {
        tables_needed.push_back(observer.table_key);
    }
    std::sort(begin(tables_needed), end(tables_needed));
    tables_needed.erase(std::unique(begin(tables_needed), end(tables_needed)), end(tables_needed));

    auto realm = context->realm.lock();
    auto& group = realm->read_group();
    for (auto& observer : observers) {
        auto table = group.get_table(TableKey(observer.table_key));
        for (auto key : table->get_column_keys()) {
            if (key.is_collection()) {
                m_lists.push_back({&observer, {}, {key}});
            }
        }
    }

    tables.reserve(tables_needed.size());
    for (auto& tbl : tables_needed)
        tables[tbl] = {};
    for (auto& list : m_lists)
        collections.push_back({list.observer->table_key, list.observer->obj_key,
                               StablePath{{StableIndex(list.col_key, 0)}}, &list.builder});
}

void KVOAdapter::before(Transaction& sg)
{
    if (!m_context)
        return;

    m_version = sg.get_version_of_current_transaction();
    if (tables.empty())
        return;

    for (auto& observer : m_observers) {
        auto it = tables.find(observer.table_key);
        if (it == tables.end())
            continue;

        auto const& table = it->second;
        auto key = observer.obj_key;
        if (m_rollback ? table.insertions_contains(key) : table.deletions_contains(key)) {
            m_invalidated.push_back(observer.info);
            continue;
        }
        auto column_modifications = table.get_columns_modified(key);
        if (column_modifications) {
            for (auto col : *column_modifications) {
                observer.changes[col.value].kind = BindingContext::ColumnInfo::Kind::Set;
            }
        }
    }

    for (auto& list : m_lists) {
        if (list.builder.empty()) {
            // We may have pre-emptively marked the column as modified if the
            // LinkList was selected but the actual changes made ended up being
            // a no-op
            list.observer->changes.erase(list.col_key.value);
            continue;
        }
        // If the containing row was deleted then changes will be empty
        if (list.observer->changes.empty()) {
            REALM_ASSERT_DEBUG(tables[list.observer->table_key].deletions_contains(list.observer->obj_key));
            continue;
        }
        // otherwise the column should have been marked as modified
        auto it = list.observer->changes.find(list.col_key.value);
        REALM_ASSERT(it != list.observer->changes.end());
        auto& builder = list.builder;
        auto& changes = it->second;

        builder.modifications.remove(builder.insertions);

        // KVO can't express moves (because NSArray doesn't have them), so
        // transform them into a series of sets on each affected index when possible
        if (!builder.moves.empty() && builder.insertions.count() == builder.moves.size() &&
            builder.deletions.count() == builder.moves.size()) {
            changes.kind = BindingContext::ColumnInfo::Kind::Set;
            changes.indices = builder.modifications;
            changes.indices.add(builder.deletions);

            // Iterate over each of the rows which may have been shifted by
            // the moves and check if it actually has been, or if it's ended
            // up in the same place as it started (either because the moves were
            // actually a swap that doesn't effect the rows in between, or the
            // combination of moves happen to leave some intermediate rows in
            // the same place)
            auto in_range = [](auto& it, auto end, size_t i) {
                if (it != end && i >= it->second)
                    ++it;
                return it != end && i >= it->first && i < it->second;
            };

            auto del_it = builder.deletions.begin(), del_end = builder.deletions.end();
            auto ins_it = builder.insertions.begin(), ins_end = builder.insertions.end();
            size_t start = std::min(ins_it->first, del_it->first);
            size_t end = std::max(std::prev(ins_end)->second, std::prev(del_end)->second);
            ptrdiff_t shift = 0;
            for (size_t i = start; i < end; ++i) {
                if (in_range(del_it, del_end, i))
                    --shift;
                else if (in_range(ins_it, ins_end, i + shift))
                    ++shift;
                if (shift != 0)
                    changes.indices.add(i);
            }
        }
        // KVO can't express multiple types of changes at once
        else if (builder.insertions.empty() + builder.modifications.empty() + builder.deletions.empty() < 2) {
            changes.kind = BindingContext::ColumnInfo::Kind::SetAll;
        }
        else if (!builder.insertions.empty()) {
            changes.kind = BindingContext::ColumnInfo::Kind::Insert;
            changes.indices = builder.insertions;
        }
        else if (!builder.modifications.empty()) {
            changes.kind = BindingContext::ColumnInfo::Kind::Set;
            changes.indices = builder.modifications;
        }
        else {
            REALM_ASSERT(!builder.deletions.empty());
            changes.kind = BindingContext::ColumnInfo::Kind::Remove;
            changes.indices = builder.deletions;
        }

        // If we're rolling back a write transaction, insertions are actually
        // deletions and vice-versa. More complicated scenarios which would
        // require logic beyond this fortunately just aren't supported by KVO.
        if (m_rollback) {
            switch (changes.kind) {
                case BindingContext::ColumnInfo::Kind::Insert:
                    changes.kind = BindingContext::ColumnInfo::Kind::Remove;
                    break;
                case BindingContext::ColumnInfo::Kind::Remove:
                    changes.kind = BindingContext::ColumnInfo::Kind::Insert;
                    break;
                default:
                    break;
            }
        }
    }
    m_context->will_change(m_observers, m_invalidated);
}

void KVOAdapter::after(Transaction& sg)
{
    if (!m_context)
        return;
    m_context->did_change(m_observers, m_invalidated,
                          m_version != VersionID{} && m_version != sg.get_version_of_current_transaction());
}

class TransactLogValidationMixin {
    // The currently selected table
    TableKey m_current_table;

    REALM_NORETURN
    REALM_NOINLINE
    void schema_error()
    {
        throw _impl::UnsupportedSchemaChange();
    }

protected:
    TableKey current_table() const noexcept
    {
        return m_current_table;
    }

public:
    bool select_table(TableKey key) noexcept
    {
        m_current_table = key;
        return true;
    }

    // Removing or renaming things while a Realm is open is never supported
    bool erase_class(TableKey)
    {
        schema_error();
    }
    bool rename_class(TableKey)
    {
        schema_error();
    }
    bool erase_column(ColKey)
    {
        schema_error();
    }
    bool rename_column(ColKey)
    {
        schema_error();
    }

    // Additive changes and reorderings are supported
    bool insert_group_level_table(TableKey)
    {
        return true;
    }
    bool insert_column(ColKey)
    {
        return true;
    }
    bool set_link_type(ColKey)
    {
        return true;
    }

    // Non-schema changes are all allowed
    void parse_complete() {}
    bool create_object(ObjKey)
    {
        return true;
    }
    bool remove_object(ObjKey)
    {
        return true;
    }
    bool collection_set(size_t)
    {
        return true;
    }
    bool collection_insert(size_t)
    {
        return true;
    }
    bool collection_erase(size_t)
    {
        return true;
    }
    bool collection_clear(size_t)
    {
        return true;
    }
    bool collection_move(size_t, size_t)
    {
        return true;
    }
    bool collection_swap(size_t, size_t)
    {
        return true;
    }
    bool typed_link_change(ColKey, TableKey)
    {
        return true;
    }
};


// A transaction log handler that just validates that all operations made are
// ones supported by the object store
struct TransactLogValidator : public TransactLogValidationMixin {
    bool modify_object(ColKey, ObjKey)
    {
        return true;
    }
    bool select_collection(ColKey, ObjKey, const StablePath&)
    {
        return true;
    }
};

// Extends TransactLogValidator to track changes made to LinkViews
class TransactLogObserver : public TransactLogValidationMixin {
    _impl::TransactionChangeInfo& m_info;
    _impl::CollectionChangeBuilder* m_active_collection = nullptr;
    ObjectChangeSet* m_active_table = nullptr;

public:
    TransactLogObserver(_impl::TransactionChangeInfo& info)
        : m_info(info)
    {
    }

    void parse_complete()
    {
        for (auto& collection : m_info.collections)
            collection.changes->clean_up_stale_moves();
        for (auto it = m_info.tables.begin(); it != m_info.tables.end();) {
            if (it->second.empty())
                it = m_info.tables.erase(it);
            else
                ++it;
        }
    }

    bool select_table(TableKey key) noexcept
    {
        TransactLogValidationMixin::select_table(key);

        TableKey table_key = current_table();
        if (auto it = m_info.tables.find(table_key); it != m_info.tables.end())
            m_active_table = &it->second;
        else
            m_active_table = nullptr;
        return true;
    }

    bool select_collection(ColKey col, ObjKey obj, const StablePath& path)
    {
        modify_object(col, obj);
        auto table = current_table();
        for (auto& c : m_info.collections) {

            if (c.table_key == table && c.obj_key == obj && c.path.is_prefix_of(path)) {
                if (c.path.size() != path.size()) {
                    StablePath sub_path;
                    sub_path.insert(sub_path.begin(), path.begin() + c.path.size(), path.end());
                    c.changes->paths.insert(std::move(sub_path));
                }
                else {
                    m_active_collection = c.changes;
                    return true;
                }
            }
        }
        m_active_collection = nullptr;
        return true;
    }

    bool collection_set(size_t index)
    {
        if (m_active_collection)
            m_active_collection->modify(index);
        return true;
    }

    bool collection_insert(size_t index)
    {
        if (m_active_collection)
            m_active_collection->insert(index);
        return true;
    }

    bool collection_erase(size_t index)
    {
        if (m_active_collection)
            m_active_collection->erase(index);
        return true;
    }

    bool collection_swap(size_t index1, size_t index2)
    {
        if (m_active_collection) {
            if (index1 > index2)
                std::swap(index1, index2);
            m_active_collection->move(index1, index2);
            if (index1 + 1 != index2)
                m_active_collection->move(index2 - 1, index1);
        }
        return true;
    }

    bool collection_clear(size_t old_size)
    {
        if (m_active_collection)
            m_active_collection->clear(old_size);
        return true;
    }

    bool collection_move(size_t from, size_t to)
    {
        if (m_active_collection)
            m_active_collection->move(from, to);
        return true;
    }

    bool create_object(ObjKey key)
    {
        if (m_active_table)
            m_active_table->insertions_add(key);
        return true;
    }

    bool remove_object(ObjKey key)
    {
        if (!m_active_table)
            return true;
        if (!m_active_table->insertions_remove(key))
            m_active_table->deletions_add(key);
        m_active_table->modifications_remove(key);

        for (size_t i = 0; i < m_info.collections.size(); ++i) {
            auto& list = m_info.collections[i];
            if (list.table_key != current_table())
                continue;
            if (list.obj_key == key) {
                if (i + 1 < m_info.collections.size())
                    m_info.collections[i] = std::move(m_info.collections.back());
                m_info.collections.pop_back();
                continue;
            }
        }

        return true;
    }

    bool modify_object(ColKey col, ObjKey key)
    {
        if (m_active_table)
            m_active_table->modifications_add(key, col);
        return true;
    }

    bool insert_column(ColKey)
    {
        m_info.schema_changed = true;
        return true;
    }

    bool insert_group_level_table(TableKey)
    {
        m_info.schema_changed = true;
        return true;
    }

    bool typed_link_change(ColKey, TableKey)
    {
        m_info.schema_changed = true;
        return true;
    }
};

class KVOTransactLogObserver : public TransactLogObserver {
    KVOAdapter m_adapter;
    _impl::NotifierPackage& m_notifiers;
    Transaction& m_sg;

public:
    KVOTransactLogObserver(std::vector<BindingContext::ObserverState>& observers, BindingContext* context,
                           _impl::NotifierPackage& notifiers, Transaction& sg, bool is_rollback = false)
        : TransactLogObserver(m_adapter)
        , m_adapter(observers, context, is_rollback)
        , m_notifiers(notifiers)
        , m_sg(sg)
    {
    }

    ~KVOTransactLogObserver()
    {
        m_adapter.after(m_sg);
    }

    void parse_complete()
    {
        TransactLogObserver::parse_complete();
        m_adapter.before(m_sg);

        m_notifiers.package_and_wait(m_sg.get_version_of_latest_snapshot());
        m_notifiers.before_advance();
    }
};

template <typename Func>
void advance_with_notifications(BindingContext* context, const std::shared_ptr<Transaction>& sg, Func&& func,
                                _impl::NotifierPackage& notifiers)
{
    auto old_version = sg->get_version_of_current_transaction();
    std::vector<BindingContext::ObserverState> observers;
    if (context) {
        observers = context->get_observed_rows();
    }

    // Advancing to the latest version with notifiers requires using the full
    // transaction log observer so that we have a point where we know what
    // version we're going to before we actually advance to that version
    if (observers.empty() && (!notifiers || notifiers.version())) {
        notifiers.before_advance();
        TransactLogValidator validator;
        func(&validator);
        auto new_version = sg->get_version_of_current_transaction();
        if (context && old_version != new_version)
            context->did_change({}, {});
        // Each of these places where we call back to the user could close the
        // Realm. Just return early if that happens.
        if (sg->get_transact_stage() == DB::transact_Ready)
            return;
        if (context)
            context->will_send_notifications();
        if (sg->get_transact_stage() == DB::transact_Ready)
            return;
        notifiers.after_advance();
        if (sg->get_transact_stage() == DB::transact_Ready)
            return;
        if (context)
            context->did_send_notifications();
        return;
    }

    if (context)
        context->will_send_notifications();
    {
        KVOTransactLogObserver observer(observers, context, notifiers, *sg);
        func(&observer);
    }
    notifiers.package_and_wait(
        sg->get_version_of_current_transaction().version); // is a no-op if parse_complete() was called
    notifiers.after_advance();
    if (context)
        context->did_send_notifications();
}

} // anonymous namespace

namespace realm {
namespace _impl {

UnsupportedSchemaChange::UnsupportedSchemaChange()
    : std::logic_error(
          "Schema mismatch detected: another process has modified the Realm file's schema in an incompatible way")
{
}

namespace transaction {
void advance(Transaction& tr, BindingContext*, VersionID version)
{
    TransactLogValidator validator;
    tr.advance_read(&validator, version);
}

void advance(const std::shared_ptr<Transaction>& tr, BindingContext* context, NotifierPackage&& notifiers)
{
    advance_with_notifications(
        context, tr,
        [&](auto&&... args) {
            tr->advance_read(std::move(args)..., notifiers.version().value_or(VersionID{}));
        },
        notifiers);
}

void begin(const std::shared_ptr<Transaction>& tr, BindingContext* context, NotifierPackage&& notifiers)
{
    advance_with_notifications(
        context, tr,
        [&](auto&&... args) {
            tr->promote_to_write(std::move(args)...);
        },
        notifiers);
}

void cancel(Transaction& tr, BindingContext* context)
{
    std::vector<BindingContext::ObserverState> observers;
    if (context) {
        observers = context->get_observed_rows();
    }
    if (observers.empty()) {
        tr.rollback_and_continue_as_read();
        return;
    }

    _impl::NotifierPackage notifiers;
    KVOTransactLogObserver o(observers, context, notifiers, tr, true);
    tr.rollback_and_continue_as_read(o);
}

void advance(Transaction& tr, TransactionChangeInfo& info, VersionID version)
{
    if (info.tables.empty() && info.collections.empty()) {
        tr.advance_read(version);
    }
    else {
        TransactLogObserver o(info);
        tr.advance_read(&o, version);
    }
}

void parse(Transaction& tr, TransactionChangeInfo& info, VersionID::version_type initial_version,
           VersionID::version_type end_version)
{
    if (!info.tables.empty() || !info.collections.empty()) {
        TransactLogObserver o(info);
        tr.parse_history(o, initial_version, end_version);
    }
}

} // namespace transaction
} // namespace _impl
} // namespace realm
