/*************************************************************************
 *
 * Copyright 2023 Realm Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************/

#include <realm/group.hpp>
#include <realm/collection.hpp>
#include <realm/bplustree.hpp>
#include <realm/array_key.hpp>
#include <realm/array_string.hpp>
#include <realm/array_mixed.hpp>
#include <realm/dictionary.hpp>
#include <realm/list.hpp>
#include <realm/util/bson/bson.hpp>

namespace realm {

namespace _impl {
size_t virtual2real(const std::vector<size_t>& vec, size_t ndx) noexcept
{
    for (auto i : vec) {
        if (i > ndx)
            break;
        ndx++;
    }
    return ndx;
}

size_t virtual2real(const BPlusTree<ObjKey>* tree, size_t ndx) noexcept
{
    // Only translate if context flag is set.
    if (tree->get_context_flag()) {
        size_t adjust = 0;
        auto func = [&adjust, ndx](BPlusTreeNode* node, size_t offset) {
            auto leaf = static_cast<BPlusTree<ObjKey>::LeafNode*>(node);
            size_t sz = leaf->size();
            for (size_t i = 0; i < sz; i++) {
                if (i + offset == ndx) {
                    return IteratorControl::Stop;
                }
                auto k = leaf->get(i);
                if (k.is_unresolved()) {
                    adjust++;
                }
            }
            return IteratorControl::AdvanceToNext;
        };

        tree->traverse(func);
        ndx -= adjust;
    }
    return ndx;
}

size_t real2virtual(const std::vector<size_t>& vec, size_t ndx) noexcept
{
    // Subtract the number of tombstones below ndx.
    auto it = std::lower_bound(vec.begin(), vec.end(), ndx);
    // A tombstone index has no virtual mapping. This is an error.
    REALM_ASSERT_DEBUG_EX(it == vec.end() || *it != ndx, ndx, vec.size());
    auto n = it - vec.begin();
    return ndx - n;
}

void update_unresolved(std::vector<size_t>& vec, const BPlusTree<ObjKey>* tree)
{
    vec.clear();

    // Only do the scan if context flag is set.
    if (tree && tree->is_attached() && tree->get_context_flag()) {
        auto func = [&vec](BPlusTreeNode* node, size_t offset) {
            auto leaf = static_cast<BPlusTree<ObjKey>::LeafNode*>(node);
            size_t sz = leaf->size();
            for (size_t i = 0; i < sz; i++) {
                auto k = leaf->get(i);
                if (k.is_unresolved()) {
                    vec.push_back(i + offset);
                }
            }
            return IteratorControl::AdvanceToNext;
        };

        tree->traverse(func);
    }
}

void check_for_last_unresolved(BPlusTree<ObjKey>* tree)
{
    if (tree) {
        bool no_more_unresolved = true;
        size_t sz = tree->size();
        for (size_t n = 0; n < sz; n++) {
            if (tree->get(n).is_unresolved()) {
                no_more_unresolved = false;
                break;
            }
        }
        if (no_more_unresolved)
            tree->set_context_flag(false);
    }
}

size_t get_collection_size_from_ref(ref_type ref, Allocator& alloc)
{
    size_t ret = 0;
    if (ref) {
        Array arr(alloc);
        arr.init_from_ref(ref);
        if (arr.is_inner_bptree_node()) {
            // This is a BPlusTree
            ret = size_t(arr.back()) >> 1;
        }
        else if (arr.has_refs()) {
            // This is a dictionary
            auto key_ref = arr.get_as_ref(0);
            ret = get_collection_size_from_ref(key_ref, alloc);
        }
        else {
            ret = arr.size();
        }
    }
    return ret;
}

} // namespace _impl

Collection::~Collection() {}

void Collection::get_any(QueryCtrlBlock& ctrl, Mixed val, size_t index)
{
    auto path_size = ctrl.path.size() - index;
    PathElement& pe = ctrl.path[index];
    if (val.is_type(type_Dictionary) && (pe.is_key() || pe.is_all())) {
        auto ref = val.get_ref();
        if (!ref)
            return;
        Array top(ctrl.alloc);
        top.init_from_ref(ref);

        BPlusTree<StringData> keys(ctrl.alloc);
        keys.set_parent(&top, 0);
        keys.init_from_parent();
        size_t start = 0;
        if (size_t finish = keys.size()) {
            if (pe.is_key()) {
                start = keys.find_first(StringData(pe.get_key()));
                if (start == realm::not_found) {
                    if (pe.get_key() == "@keys") {
                        keys.for_all([&](const auto& k) {
                            ctrl.matches.insert(k);
                        });
                    }
                    return;
                }
                finish = start + 1;
            }
            BPlusTree<Mixed> values(ctrl.alloc);
            values.set_parent(&top, 1);
            values.init_from_parent();
            for (; start < finish; start++) {
                val = values.get(start);
                if (path_size > 1) {
                    Collection::get_any(ctrl, val, index + 1);
                }
                else {
                    ctrl.matches.insert(val);
                }
            }
        }
    }
    else if (val.is_type(type_List) && (pe.is_ndx() || pe.is_all())) {
        auto ref = val.get_ref();
        if (!ref)
            return;
        BPlusTree<Mixed> list(ctrl.alloc);
        list.init_from_ref(ref);
        if (size_t sz = list.size()) {
            size_t start = 0;
            size_t finish = sz;
            if (pe.is_ndx()) {
                start = pe.get_ndx();
                if (start == size_t(-1)) {
                    start = sz - 1;
                }
                if (start < sz) {
                    finish = start + 1;
                }
            }
            for (; start < finish; start++) {
                val = list.get(start);
                if (path_size > 1) {
                    Collection::get_any(ctrl, val, index + 1);
                }
                else {
                    ctrl.matches.insert(val);
                }
            }
        }
    }
    else if (val.is_type(type_TypedLink) && pe.is_key()) {
        auto link = val.get_link();
        Obj obj = ctrl.group->get_object(link);
        auto col = obj.get_table()->get_column_key(pe.get_key());
        if (col) {
            val = obj.get_any(col);
            if (path_size > 1) {
                if (val.is_type(type_Link)) {
                    val = ObjLink(obj.get_target_table(col)->get_key(), val.get<ObjKey>());
                }
                Collection::get_any(ctrl, val, index + 1);
            }
            else {
                ctrl.matches.insert(val);
            }
        }
    }
}

bson::Bson CollectionBase::link_to_bson(ObjKey obj_key) const
{
    REALM_ASSERT(obj_key);
    auto target_table = get_obj().get_target_table(get_col_key());
    auto obj = target_table->get_object(obj_key);
    if (target_table->is_embedded()) {
        bson::BsonDocument doc;
        obj.to_bson(doc);
        return doc;
    }
    else {
        return obj.get_primary_key().to_bson();
    }
}

bson::Bson CollectionBase::mixed_to_bson(Mixed value) const
{
    if (value.is_type(type_Dictionary)) {
        DummyParent parent(get_obj().get_table(), value.get_ref());
        Dictionary dict(parent, 0);
        bson::BsonDocument doc;
        dict.to_bson(doc);
        return doc;
    }
    else if (value.is_type(type_List)) {
        DummyParent parent(get_obj().get_table(), value.get_ref());
        Lst<Mixed> list(parent, 0);
        bson::BsonArray arr;
        list.to_bson(arr);
        return arr;
    }
    else if (value.is_type(type_TypedLink)) {
        bson::BsonDocument link;
        {
            bson::BsonDocument sub_doc = link.append_document("$link");
            auto obj = get_table()->get_parent_group()->get_object(value.get_link());
            auto target_table = obj.get_table();
            sub_doc.append("table", std::string(target_table->get_class_name()));
            sub_doc.append("key", obj.get_primary_key().to_bson());
        }
        return link;
    }
    else {
        return value.to_bson();
    }
}

ObjLink CollectionBase::is_link(const bson::BsonDocument& document)
{
    auto it = document.find("$link");
    if (it != document.end()) {
        auto sub_doc = static_cast<const bson::BsonDocument&>((*it).second);
        std::string table_name = static_cast<const std::string&>(sub_doc["table"]);
        Mixed pk(sub_doc["key"]);
        Group::TableNameBuffer buffer;
        auto table = get_table()->get_parent_group()->get_table(Group::class_name_to_table_name(table_name, buffer));
        return {table->get_key(), table->get_objkey_from_primary_key(pk)};
    }
    return {};
}

std::pair<std::string, std::string> CollectionBase::get_open_close_strings(size_t link_depth,
                                                                           JSONOutputMode output_mode) const
{
    std::string open_str;
    std::string close_str;
    auto collection_type = get_collection_type();
    Table* target_table = get_target_table().unchecked_ptr();
    auto ck = get_col_key();
    auto type = ck.get_type();
    if (type == col_type_Link) {
        bool is_embedded = target_table->is_embedded();
        bool link_depth_reached = !is_embedded && (link_depth == 0);

        if (output_mode == output_mode_xjson_plus) {
            open_str = std::string("{ ") + (is_embedded ? "\"$embedded" : "\"$link");
            open_str += collection_type_name(collection_type, true);
            open_str += "\": ";
            close_str += " }";
        }

        if ((link_depth_reached && output_mode != output_mode_xjson) || output_mode == output_mode_xjson_plus) {
            open_str += "{ \"table\": \"" + std::string(target_table->get_name()) + "\", ";
            open_str += ((is_embedded || collection_type == CollectionType::Dictionary) ? "\"values" : "\"keys");
            open_str += "\": ";
            close_str += "}";
        }
    }
    else {
        if (output_mode == output_mode_xjson_plus) {
            switch (collection_type) {
                case CollectionType::List:
                    break;
                case CollectionType::Set:
                    open_str = "{ \"$set\": ";
                    close_str = " }";
                    break;
                case CollectionType::Dictionary:
                    open_str = "{ \"$dictionary\": ";
                    close_str = " }";
                    break;
            }
        }
    }
    return {open_str, close_str};
}

} // namespace realm
