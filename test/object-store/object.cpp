////////////////////////////////////////////////////////////////////////////
//
// Copyright 2017 Realm Inc.
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

#include <catch2/catch_all.hpp>

#include "util/event_loop.hpp"
#include "util/index_helpers.hpp"
#include "util/test_file.hpp"
#include "util/test_utils.hpp"

#include <realm/object-store/feature_checks.hpp>
#include <realm/object-store/collection_notifications.hpp>
#include <realm/object-store/object_accessor.hpp>
#include <realm/object-store/property.hpp>
#include <realm/object-store/schema.hpp>
#include <realm/object-store/object.hpp>
#include <realm/object-store/util/scheduler.hpp>

#include <realm/object-store/impl/realm_coordinator.hpp>
#include <realm/object-store/impl/object_accessor_impl.hpp>

#include <realm/group.hpp>
#include <realm/sync/subscriptions.hpp>
#include <realm/util/any.hpp>

#include <cstdint>

using namespace realm;
using util::any_cast;

namespace {
using AnyDict = std::map<std::string, std::any>;
using AnyVec = std::vector<std::any>;
template <class T>
std::vector<T> get_vector(std::initializer_list<T> list)
{
    return std::vector<T>(list);
}
} // namespace

struct TestContext : CppContext {
    std::map<std::string, AnyDict> defaults;

    using CppContext::CppContext;
    TestContext(TestContext& parent, realm::Obj& obj, realm::Property const& prop)
        : CppContext(parent, obj, prop)
        , defaults(parent.defaults)
    {
    }

    util::Optional<std::any> default_value_for_property(ObjectSchema const& object, Property const& prop)
    {
        auto obj_it = defaults.find(object.name);
        if (obj_it == defaults.end())
            return util::none;
        auto prop_it = obj_it->second.find(prop.name);
        if (prop_it == obj_it->second.end())
            return util::none;
        return prop_it->second;
    }

    void will_change(Object const&, Property const&) {}
    void did_change() {}
    std::string print(std::any)
    {
        return "not implemented";
    }
    bool allow_missing(std::any)
    {
        return false;
    }

    template <class T>
    T get(Object& obj, const std::string& name)
    {
        return util::any_cast<T>(obj.get_property_value<std::any>(*this, name));
    }
};

class CreatePolicyRecordingContext {
public:
    CreatePolicyRecordingContext(CreatePolicyRecordingContext&, Obj, Property const&) {}
    CreatePolicyRecordingContext() = default;
    CreatePolicyRecordingContext(std::shared_ptr<Realm>, const ObjectSchema*) {}

    util::Optional<std::any> value_for_property(std::any&, const Property&, size_t) const
    {
        return util::none;
    }

    template <typename Func>
    void enumerate_collection(std::any&, Func&&)
    {
    }

    template <typename Func>
    void enumerate_dictionary(std::any&, Func&&)
    {
    }

    bool is_same_set(object_store::Set const&, std::any const&)
    {
        return false;
    }

    bool is_same_list(List const&, std::any const&)
    {
        return false;
    }

    bool is_same_dictionary(const object_store::Dictionary&, const std::any&)
    {
        return false;
    }

    std::any box(Mixed v) const
    {
        return v;
    }

    template <typename T>
    T unbox(std::any& v, CreatePolicy p, ObjKey = ObjKey()) const
    {
        last_create_policy = p;
        return util::any_cast<T>(v);
    }

    bool is_null(std::any const& v) const noexcept
    {
        return !v.has_value();
    }
    std::any null_value() const noexcept
    {
        return {};
    }

    void will_change(Object const&, Property const&) {}
    void did_change() {}

    mutable CreatePolicy last_create_policy;
};

TEST_CASE("object") {
    using namespace std::string_literals;
    _impl::RealmCoordinator::assert_no_open_realms();

    InMemoryTestFile config;
    config.automatic_change_notifications = false;
    config.schema_mode = SchemaMode::AdditiveExplicit;
    config.schema = Schema{
        {"table",
         {
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"value 1", PropertyType::Int},
             {"value 2", PropertyType::Int},
         },
         {
             {"origin", PropertyType::LinkingObjects | PropertyType::Array, "table2", "link"},
         }},
        {"table2",
         {
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"value", PropertyType::Int},
             {"link", PropertyType::Object | PropertyType::Nullable, "table"},
             {"link2", PropertyType::Object | PropertyType::Array, "table2"},
         },
         {
             {"parent", PropertyType::LinkingObjects | PropertyType::Array, "table2", "link2"},
         }},
        {"all types",
         {
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"bool", PropertyType::Bool},
             {"int", PropertyType::Int},
             {"float", PropertyType::Float},
             {"double", PropertyType::Double},
             {"string", PropertyType::String},
             {"data", PropertyType::Data},
             {"date", PropertyType::Date},
             {"object id", PropertyType::ObjectId},
             {"decimal", PropertyType::Decimal},
             {"uuid", PropertyType::UUID},
             {"mixed", PropertyType::Mixed | PropertyType::Nullable, Property::IsPrimary{false},
              Property::IsIndexed{true}},
             {"object", PropertyType::Object | PropertyType::Nullable, "link target"},

             {"bool array", PropertyType::Array | PropertyType::Bool},
             {"int array", PropertyType::Array | PropertyType::Int},
             {"float array", PropertyType::Array | PropertyType::Float},
             {"double array", PropertyType::Array | PropertyType::Double},
             {"string array", PropertyType::Array | PropertyType::String},
             {"data array", PropertyType::Array | PropertyType::Data},
             {"date array", PropertyType::Array | PropertyType::Date},
             {"object array", PropertyType::Array | PropertyType::Object, "array target"},
             {"object id array", PropertyType::Array | PropertyType::ObjectId},
             {"uuid array", PropertyType::Array | PropertyType::UUID},
             {"decimal array", PropertyType::Array | PropertyType::Decimal},
             {"mixed array", PropertyType::Array | PropertyType::Mixed | PropertyType::Nullable},

             {"dictionary", PropertyType::Dictionary | PropertyType::String},
         }},
        {"all optional types",
         {
             {"_id", PropertyType::Int | PropertyType::Nullable, Property::IsPrimary{true}},
             {"bool", PropertyType::Bool | PropertyType::Nullable},
             {"int", PropertyType::Int | PropertyType::Nullable},
             {"float", PropertyType::Float | PropertyType::Nullable},
             {"double", PropertyType::Double | PropertyType::Nullable},
             {"string", PropertyType::String | PropertyType::Nullable},
             {"data", PropertyType::Data | PropertyType::Nullable},
             {"date", PropertyType::Date | PropertyType::Nullable},
             {"object id", PropertyType::ObjectId | PropertyType::Nullable},
             {"decimal", PropertyType::Decimal | PropertyType::Nullable},
             {"uuid", PropertyType::UUID | PropertyType::Nullable},
             {"mixed", PropertyType::Mixed | PropertyType::Nullable, Property::IsPrimary{false},
              Property::IsIndexed{true}},

             {"bool array", PropertyType::Array | PropertyType::Bool | PropertyType::Nullable},
             {"int array", PropertyType::Array | PropertyType::Int | PropertyType::Nullable},
             {"float array", PropertyType::Array | PropertyType::Float | PropertyType::Nullable},
             {"double array", PropertyType::Array | PropertyType::Double | PropertyType::Nullable},
             {"string array", PropertyType::Array | PropertyType::String | PropertyType::Nullable},
             {"data array", PropertyType::Array | PropertyType::Data | PropertyType::Nullable},
             {"date array", PropertyType::Array | PropertyType::Date | PropertyType::Nullable},
             {"object id array", PropertyType::Array | PropertyType::ObjectId | PropertyType::Nullable},
             {"decimal array", PropertyType::Array | PropertyType::Decimal | PropertyType::Nullable},
             {"uuid array", PropertyType::Array | PropertyType::UUID | PropertyType::Nullable},
         }},
        {"link target",
         {
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"value", PropertyType::Int},
         },
         {
             {"origin", PropertyType::LinkingObjects | PropertyType::Array, "all types", "object"},
         }},
        {"array target",
         {
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"value", PropertyType::Int},
         }},
        {"pk after list",
         {
             {"array 1", PropertyType::Array | PropertyType::Object, "array target"},
             {"int 1", PropertyType::Int},
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"int 2", PropertyType::Int},
             {"array 2", PropertyType::Array | PropertyType::Object, "array target"},
         }},
        {"nullable int pk",
         {
             {"_id", PropertyType::Int | PropertyType::Nullable, Property::IsPrimary{true}},
         }},
        {"nullable string pk",
         {
             {"_id", PropertyType::String | PropertyType::Nullable, Property::IsPrimary{true}},
         }},
        {"nullable object id pk",
         {
             {"_id", PropertyType::ObjectId | PropertyType::Nullable, Property::IsPrimary{true}},
         }},
        {"nullable uuid pk",
         {
             {"_id", PropertyType::UUID | PropertyType::Nullable, Property::IsPrimary{true}},
         }},
        {"person",
         {
             {"_id", PropertyType::String, Property::IsPrimary{true}},
             {"age", PropertyType::Int},
             {"scores", PropertyType::Array | PropertyType::Int},
             {"assistant", PropertyType::Object | PropertyType::Nullable, "person"},
             {"team", PropertyType::Array | PropertyType::Object, "person"},
         }},
    };
    config.schema_version = 0;
    auto r = Realm::get_shared_realm(config);
    auto& coordinator = *_impl::RealmCoordinator::get_coordinator(config.path);

    TestContext d(r);
    auto create = [&](std::any&& value, CreatePolicy policy = CreatePolicy::ForceCreate) {
        r->begin_transaction();
        auto obj = Object::create(d, r, *r->schema().find("all types"), value, policy);
        r->commit_transaction();
        return obj;
    };
    auto create_sub = [&](std::any&& value, CreatePolicy policy = CreatePolicy::ForceCreate) {
        r->begin_transaction();
        auto obj = Object::create(d, r, *r->schema().find("link target"), value, policy);
        r->commit_transaction();
        return obj;
    };
    auto create_company = [&](std::any&& value, CreatePolicy policy = CreatePolicy::ForceCreate) {
        r->begin_transaction();
        Object obj = Object::create(d, r, *r->schema().find("person"), value, policy);
        r->commit_transaction();
        return obj;
    };

    SECTION("add_notification_callback()") {
        auto table = r->read_group().get_table("class_table");
        auto col_keys = table->get_column_keys();
        std::vector<int64_t> pks = {3, 4, 7, 9, 10, 21, 24, 34, 42, 50};
        r->begin_transaction();
        for (int i = 0; i < 10; ++i)
            table->create_object_with_primary_key(pks[i]).set("value 1", i).set("value 2", i);
        r->commit_transaction();

        auto r2 = coordinator.get_realm();

        CollectionChangeSet change;
        auto obj = *table->begin();
        Object object(r, obj);

        auto write = [&](auto&& f) {
            r->begin_transaction();
            f();
            r->commit_transaction();

            advance_and_notify(*r);
        };

        auto require_change = [&](Object& object, std::optional<KeyPathArray> key_path_array = std::nullopt) {
            auto token = object.add_notification_callback(
                [&](CollectionChangeSet c) {
                    change = c;
                },
                key_path_array);
            advance_and_notify(*r);
            return token;
        };

        auto require_no_change = [&](Object& object, std::optional<KeyPathArray> key_path_array = std::nullopt) {
            bool first = true;
            auto token = object.add_notification_callback(
                [&](CollectionChangeSet) {
                    REQUIRE(first);
                    first = false;
                },
                key_path_array);
            advance_and_notify(*r);
            return token;
        };

        SECTION("deleting the object sends a change notification") {
            auto token = require_change(object);
            write([&] {
                obj.remove();
            });
            REQUIRE_INDICES(change.deletions, 0);
        }

        SECTION("unregistering prior to deleting the object sends no notification") {
            auto token = require_no_change(object);
            token.unregister();
            write([&] {
                obj.remove();
            });
        }

        SECTION("deleting object before first run of notifier") {
            auto token = object.add_notification_callback(
                [&](CollectionChangeSet c) {
                    change = std::move(c);
                },
                {});
            // Delete via a different Realm as begin_transaction() will wait
            // for the notifier to run
            r2->begin_transaction();
            r2->read_group().get_table("class_table")->begin()->remove();
            r2->commit_transaction();
            advance_and_notify(*r);
            REQUIRE_INDICES(change.deletions, 0);
            write([] {});
        }

        SECTION("clearing the table sends a change notification") {
            auto token = require_change(object);
            write([&] {
                table->clear();
            });
            REQUIRE_INDICES(change.deletions, 0);
        }

        SECTION("clearing the table sends a change notification to the last object") {
            obj = table->get_object(table->size() - 1);
            object = Object(r, obj);

            auto token = require_change(object);
            write([&] {
                table->clear();
            });
            REQUIRE_INDICES(change.deletions, 0);
        }

        SECTION("modifying the object sends a change notification") {
            auto token = require_change(object);

            write([&] {
                obj.set(col_keys[0], 10);
            });
            REQUIRE_INDICES(change.modifications, 0);
            REQUIRE(change.columns.size() == 1);
            REQUIRE_INDICES(change.columns[col_keys[0].value], 0);

            write([&] {
                obj.set(col_keys[1], 10);
            });
            REQUIRE_INDICES(change.modifications, 0);
            REQUIRE(change.columns.size() == 1);
            REQUIRE_INDICES(change.columns[col_keys[1].value], 0);
        }

        SECTION("modifying a different object") {
            auto token = require_no_change(object);
            write([&] {
                table->get_object(1).set(col_keys[0], 10);
            });
        }

        SECTION("multiple write transactions") {
            auto token = require_change(object);

            auto r2row = r2->read_group().get_table("class_table")->get_object(0);
            r2->begin_transaction();
            r2row.set(col_keys[0], 1);
            r2->commit_transaction();
            r2->begin_transaction();
            r2row.set(col_keys[1], 2);
            r2->commit_transaction();

            advance_and_notify(*r);
            REQUIRE(change.columns.size() == 2);
            REQUIRE_INDICES(change.columns[col_keys[0].value], 0);
            REQUIRE_INDICES(change.columns[col_keys[1].value], 0);
        }

        SECTION("skipping a notification") {
            auto token = require_no_change(object);
            write([&] {
                obj.set(col_keys[0], 1);
                token.suppress_next();
            });
        }

        SECTION("skipping only effects the current transaction even if no notification would occur anyway") {
            auto token = require_change(object);

            // would not produce a notification even if it wasn't skipped because no changes were made
            write([&] {
                token.suppress_next();
            });
            REQUIRE(change.empty());

            // should now produce a notification
            write([&] {
                obj.set(col_keys[0], 1);
            });
            REQUIRE_INDICES(change.modifications, 0);
        }

        SECTION("add notification callback, remove it, then add another notification callback") {
            {
                auto token = object.add_notification_callback([&](CollectionChangeSet) {
                    FAIL("This should never happen");
                });
            }
            auto token = require_change(object);
            write([&] {
                obj.remove();
            });
            REQUIRE_INDICES(change.deletions, 0);
        }

        SECTION("observing deleted object throws") {
            write([&] {
                obj.remove();
            });
            REQUIRE_EXCEPTION(require_change(object), InvalidatedObject,
                              "Accessing object of type table which has been invalidated or deleted");
        }

        SECTION("keypath filtered notifications") {
            auto table_origin = r->read_group().get_table("class_table2");
            auto col_origin_value = table_origin->get_column_key("value");
            auto col_origin_link = table_origin->get_column_key("link");
            auto col_origin_link2 = table_origin->get_column_key("link2");

            auto table_target = r->read_group().get_table("class_table");
            auto col_target_value1 = table_target->get_column_key("value 1");
            auto col_target_value2 = table_target->get_column_key("value 2");
            auto col_target_backlink = table_origin->get_opposite_column(col_origin_link);

            r->begin_transaction();

            Obj obj_target = table_target->create_object_with_primary_key(200);
            Object object_target(r, obj_target);
            object_target.set_column_value("value 1", 201);
            object_target.set_column_value("value 2", 202);

            Obj obj_origin = table_origin->create_object_with_primary_key(100);
            Object object_origin(r, obj_origin);
            object_origin.set_column_value("value", 101);
            object_origin.set_property_value(d, "link", std::any(object_target));

            r->commit_transaction();

            KeyPathArray kpa_origin_value = r->create_key_path_array("table2", {"value"});
            KeyPathArray kpa_origin_link = r->create_key_path_array("table2", {"link"});
            KeyPathArray kpa_target_value1 = r->create_key_path_array("table", {"value 1"});
            KeyPathArray kpa_target_value2 = r->create_key_path_array("table", {"value 2"});

            KeyPathArray kpa_origin_to_target_value1 = r->create_key_path_array("table2", {"link.value 1"});
            KeyPathArray kpa_origin_to_target_value2 = r->create_key_path_array("table2", {"link.value 2"});
            KeyPathArray kpa_target_backlink = r->create_key_path_array("table", {"origin"});
            KeyPathArray kpa_target_to_origin_value = r->create_key_path_array("table", {"origin.value"});
            KeyPathArray kpa_target_to_origin_link = r->create_key_path_array("table", {"origin.link"});

            SECTION("callbacks on a single object") {
                SECTION("modifying origin table 'table2', property 'value' "
                        "while observing origin table 'table2', property 'value' "
                        "-> DOES send a notification") {
                    auto token = require_change(object_origin, kpa_origin_value);

                    write([&] {
                        object_origin.set_column_value("value", 105);
                    });
                    REQUIRE_INDICES(change.modifications, 0);
                    REQUIRE(change.columns.size() == 1);
                    REQUIRE_INDICES(change.columns[col_origin_value.value], 0);
                }

                SECTION("modifying related table 'table', property 'value 1' "
                        "while observing related table 'table', property 'value 1' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_origin, kpa_origin_value);

                    write([&] {
                        object_target.set_column_value("value 1", 205);
                    });
                }

                SECTION("modifying related table 'table', property 'value 2' "
                        "while observing related table 'table', property 'value 2' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_origin, kpa_origin_value);

                    write([&] {
                        object_target.set_column_value("value 2", 205);
                    });
                }

                SECTION("modifying origin table 'table2', property 'value' "
                        "while observing related table 'table', property 'value 1' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_target, kpa_target_value1);

                    write([&] {
                        object_origin.set_column_value("value", 105);
                    });
                }

                SECTION("modifying related table 'table', property 'value 1' "
                        "while observing related table 'table', property 'value 1' "
                        "-> DOES send a notification") {
                    auto token = require_change(object_target, kpa_target_value1);

                    write([&] {
                        object_target.set_column_value("value 1", 205);
                    });
                    REQUIRE_INDICES(change.modifications, 0);
                    REQUIRE(change.columns.size() == 1);
                    REQUIRE_INDICES(change.columns[col_target_value1.value], 0);
                }

                SECTION("modifying related table 'table', property 'value 2' "
                        "while observing related table 'table', property 'value 1' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_target, kpa_target_value1);

                    write([&] {
                        object_target.set_column_value("value 2", 205);
                    });
                }

                SECTION("modifying origin table 'table2', property 'value' "
                        "while observing related table 'table', property 'value 2' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_target, kpa_target_value2);

                    write([&] {
                        object_origin.set_column_value("value", 105);
                    });
                }

                SECTION("modifying related table 'table', property 'value 1' "
                        "while observing related table 'table', property 'value 2' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_target, kpa_target_value2);

                    write([&] {
                        object_target.set_column_value("value 1", 205);
                    });
                }

                SECTION("modifying related table 'table', property 'value 2' "
                        "while observing related table 'table', property 'value 2' "
                        "-> DOES send a notification") {
                    auto token = require_change(object_target, kpa_target_value2);

                    write([&] {
                        object_target.set_column_value("value 2", 205);
                    });
                    REQUIRE_INDICES(change.modifications, 0);
                    REQUIRE(change.columns.size() == 1);
                    REQUIRE_INDICES(change.columns[col_target_value2.value], 0);
                }
            }

            SECTION("callbacks on linked objects") {
                SECTION("all callbacks filtered") {
                    SECTION("modifying origin table 'table2', property 'value' "
                            "while observing related table 'table', property 'value 1' "
                            "-> does NOT send a notification") {
                        auto token = require_no_change(object_origin, kpa_origin_to_target_value1);

                        write([&] {
                            object_origin.set_column_value("value", 105);
                        });
                    }

                    SECTION("modifying related table 'table', property 'value 1' "
                            "while observing related table 'table', property 'value 1' "
                            "-> DOES send a notification") {
                        auto token = require_change(object_origin, kpa_origin_to_target_value1);

                        write([&] {
                            object_target.set_column_value("value 1", 205);
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_origin_link.value], 0);
                    }

                    SECTION("modifying related table 'table', property 'value 2' "
                            "while observing related table 'table', property 'value 1' "
                            "-> does NOT send a notification") {
                        auto token = require_no_change(object_origin, kpa_origin_to_target_value1);

                        write([&] {
                            object_target.set_column_value("value 2", 205);
                        });
                    }
                }

                SECTION("some callbacks filtered") {
                    SECTION("modifying origin table 'table2', property 'value' "
                            "while observing related table 'table', property 'value 1' "
                            "-> DOES send a notification") {
                        auto token_with_filter = require_change(object_origin, kpa_origin_to_target_value1);
                        auto token_without_filter = require_change(object_origin);

                        write([&] {
                            object_origin.set_column_value("value", 105);
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_origin_value.value], 0);
                    }

                    SECTION("modifying related table 'table', property 'value 1' "
                            "while observing related table 'table', property 'value 1' "
                            "-> DOES send a notification") {
                        auto token_with_filter = require_change(object_origin, kpa_origin_to_target_value1);
                        auto token_without_filter = require_change(object_origin);

                        write([&] {
                            object_target.set_column_value("value 1", 205);
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_origin_link.value], 0);
                    }

                    SECTION("modifying related table 'table', property 'value 2' "
                            "while observing related table 'table', property 'value 1' "
                            "-> does NOT send a notification") {
                        auto token_with_filter = require_no_change(object_origin, kpa_origin_to_target_value1);
                        auto token_without_filter = require_no_change(object_origin);

                        write([&] {
                            object_target.set_column_value("value 2", 205);
                        });
                    }
                }
            }

            SECTION("callback with empty keypatharray") {
                SECTION("modifying origin table 'table2', property 'value' "
                        "while observing related table 'table', property 'value 1' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_origin, KeyPathArray());

                    write([&] {
                        object_origin.set_column_value("value", 105);
                    });
                }

                SECTION("modifying related table 'table', property 'value 1' "
                        "while observing related table 'table', property 'value 1' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_origin, KeyPathArray());

                    write([&] {
                        object_target.set_column_value("value 1", 205);
                    });
                }

                SECTION("modifying related table 'table', property 'value 2' "
                        "while observing related table 'table', property 'value 1' "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_origin, KeyPathArray());

                    write([&] {
                        object_target.set_column_value("value 2", 205);
                    });
                }
            }

            SECTION("callback with empty keypatharray, backlinks") {
                SECTION("modifying backlinked table 'table2', property 'value' "
                        "with empty KeyPathArray "
                        "-> DOES not send a notification") {
                    auto token_with_shallow_subscribtion = require_no_change(object_target, KeyPathArray());
                    write([&] {
                        object_origin.set_column_value("value", 105);
                    });
                }
                SECTION("modifying backlinked table 'table2', property 'link' "
                        "with empty KeyPathArray "
                        "-> does NOT send a notification") {
                    auto token_with_empty_key_path_array = require_no_change(object_target, KeyPathArray());
                    write([&] {
                        Obj obj_target2 = table_target->create_object_with_primary_key(300);
                        Object object_target2(r, obj_target2);
                        object_origin.set_property_value(d, "link", std::any(object_target2));
                    });
                }
                SECTION("adding a new origin pointing to the target "
                        "with empty KeyPathArray "
                        "-> does NOT send a notification") {
                    auto token_with_empty_key_path_array = require_no_change(object_target, KeyPathArray());
                    write([&] {
                        Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                        Object object_origin2(r, obj_origin2);
                        object_origin2.set_property_value(d, "link", std::any(object_target));
                    });
                }
                SECTION("adding a new origin pointing to the target "
                        "with empty KeyPathArray "
                        "-> does NOT send a notification") {
                    auto token_with_empty_key_path_array = require_no_change(object_target, KeyPathArray());
                    write([&] {
                        Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                        Object object_origin2(r, obj_origin2);
                        object_origin2.set_property_value(d, "link", std::any(object_target));
                    });
                }
            }

            SECTION("callbacks on objects with link depth > 4") {
                r->begin_transaction();

                Obj obj_depth6 = table_origin->create_object_with_primary_key(600);
                Object object_depth6(r, obj_depth6);
                object_depth6.set_column_value("value", 601);

                Obj obj_depth5 = table_origin->create_object_with_primary_key(500);
                Object object_depth5(r, obj_depth5);
                object_depth5.set_column_value("value", 501);
                object_depth5.set_property_value(d, "link2", std::any(AnyVec{std::any(object_depth6)}));

                Obj obj_depth4 = table_origin->create_object_with_primary_key(400);
                Object object_depth4(r, obj_depth4);
                object_depth4.set_column_value("value", 401);
                object_depth4.set_property_value(d, "link2", std::any(AnyVec{std::any(object_depth5)}));

                Obj obj_depth3 = table_origin->create_object_with_primary_key(300);
                Object object_depth3(r, obj_depth3);
                object_depth3.set_column_value("value", 301);
                object_depth3.set_property_value(d, "link2", std::any(AnyVec{std::any(object_depth4)}));

                Obj obj_depth2 = table_origin->create_object_with_primary_key(200);
                Object object_depth2(r, obj_depth2);
                object_depth2.set_column_value("value", 201);
                object_depth2.set_property_value(d, "link2", std::any(AnyVec{std::any(object_depth3)}));

                Obj obj_depth1 = table_origin->create_object_with_primary_key(100);
                Object object_depth1(r, obj_depth1);
                object_depth1.set_column_value("value", 101);
                object_depth1.set_property_value(d, "link2", std::any(AnyVec{std::any(object_depth2)}));

                r->commit_transaction();

                KeyPathArray kpa_to_depth_5 = r->create_key_path_array("table2", {"link2.link2.link2.link2.value"});
                KeyPathArray kpa_to_depth_6 =
                    r->create_key_path_array("table2", {"link2.link2.link2.link2.link2.value"});

                SECTION("modifying table 'table2', property 'link2' 5 levels deep "
                        "while observing table 'table2', property 'link2' 5 levels deep "
                        "-> DOES send a notification") {
                    auto token = require_change(object_depth1, kpa_to_depth_5);

                    write([&] {
                        object_depth5.set_column_value("value", 555);
                    });
                    REQUIRE_INDICES(change.modifications, 0);
                    REQUIRE(change.columns.size() == 1);
                    REQUIRE_INDICES(change.columns[col_origin_link2.value], 0);
                }

                SECTION("modifying table 'table2', property 'link2' 6 depths deep "
                        "while observing table 'table2', property 'link2' 5 depths deep "
                        "-> does NOT send a notification") {
                    auto token = require_no_change(object_depth1, kpa_to_depth_5);

                    write([&] {
                        object_depth6.set_column_value("value", 555);
                    });
                }
            }

            SECTION("keypath filter with a backlink") {
                SECTION("all callbacks filtered") {
                    SECTION("modifying backlinked table 'table2', property 'value' "
                            "while observing backlinked table 'table2', property 'value' on origin "
                            "-> DOES send a notification") {
                        auto token_with_backlink = require_change(object_target, kpa_target_to_origin_value);
                        write([&] {
                            object_origin.set_column_value("value", 105);
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                    }
                    SECTION("modifying backlinked table 'table2', property 'link' "
                            "while observing backlinked table 'table2', property 'value' on origin "
                            "-> does NOT send a notification") {
                        auto token_with_backlink = require_no_change(object_target, kpa_target_to_origin_value);
                        write([&] {
                            Obj obj_target2 = table_target->create_object_with_primary_key(300);
                            Object object_target2(r, obj_target2);
                            object_origin.set_property_value(d, "link", std::any(object_target2));
                        });
                    }
                }

                SECTION("adding a new origin pointing to the target "
                        "while observing target table 'table2's backlink "
                        "-> DOES send a notification") {
                    auto token_with_backlink = require_change(object_target, kpa_target_backlink);
                    write([&] {
                        Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                        Object object_origin2(r, obj_origin2);
                        object_origin2.set_property_value(d, "link", std::any(object_target));
                    });
                    REQUIRE_INDICES(change.modifications, 0);
                    REQUIRE(change.columns.size() == 1);
                    REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                }

                SECTION("adding a new origin pointing to the target "
                        "while observing target table 'table2', property 'link' on origin "
                        "-> DOES send a notification") {
                    auto token_with_backlink = require_change(object_target, kpa_target_to_origin_link);
                    write([&] {
                        Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                        Object object_origin2(r, obj_origin2);
                        object_origin2.set_property_value(d, "link", std::any(object_target));
                    });
                    REQUIRE_INDICES(change.modifications, 0);
                    REQUIRE(change.columns.size() == 1);
                    REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                }

                SECTION("adding a new origin pointing to the target "
                        "while observing target table 'table2', property 'value' on origin "
                        "-> DOES send a notification") {
                    auto token_with_backlink = require_change(object_target, kpa_target_to_origin_value);
                    write([&] {
                        Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                        Object object_origin2(r, obj_origin2);
                        object_origin2.set_property_value(d, "link", std::any(object_target));
                    });
                    REQUIRE_INDICES(change.modifications, 0);
                    REQUIRE(change.columns.size() == 1);
                    REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                }

                SECTION("some callbacks filtered") {
                    SECTION("modifying backlinked table 'table2', property 'value' "
                            "while observing backlinked table 'table2', property 'value' on origin "
                            "-> DOES send a notification") {
                        auto token_with_backlink = require_change(object_target, kpa_target_to_origin_value);
                        auto token_without_filter = require_change(object_target);
                        write([&] {
                            object_origin.set_column_value("value", 105);
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                    }
                    SECTION("modifying backlinked table 'table2', property 'link2' "
                            "while observing backlinked table 'table2', property 'value' on origin "
                            "-> does NOT a notification") {
                        auto token_with_backlink = require_no_change(object_target, kpa_target_to_origin_value);
                        auto token_without_filter = require_no_change(object_target);
                        write([&] {
                            Obj obj_target2 = table_target->create_object_with_primary_key(300);
                            Object object_target2(r, obj_target2);
                            object_origin.set_property_value(d, "link", std::any(object_target2));
                        });
                    }
                    SECTION("adding a new origin pointing to the target "
                            "while observing target table 'table2's backlink "
                            "-> DOES send a notification") {
                        auto token_with_backlink = require_change(object_target, kpa_target_backlink);
                        auto token_without_filter = require_change(object_target);
                        write([&] {
                            Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                            Object object_origin2(r, obj_origin2);
                            object_origin2.set_property_value(d, "link", std::any(object_target));
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                    }
                    SECTION("adding a new origin pointing to the target "
                            "while observing target table 'table2', property 'value' on origin "
                            "-> DOES send a notification") {
                        auto token_with_backlink = require_change(object_target, kpa_target_to_origin_value);
                        auto token_without_filter = require_change(object_target);
                        write([&] {
                            Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                            Object object_origin2(r, obj_origin2);
                            object_origin2.set_property_value(d, "link", std::any(object_target));
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                    }
                    SECTION("changes to backlink are reported both to origin and destination object") {
                        Object object_origin2;
                        write([&] {
                            Obj obj_origin2 = table_origin->create_object_with_primary_key(300);
                            object_origin2 = Object{r, obj_origin2};
                        });

                        // add a backlink
                        auto token_with_backlink = require_change(object_target, kpa_target_backlink);
                        write([&] {
                            object_origin2.set_property_value(d, "link", util::Any(object_target));
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);

                        // nullify a backlink
                        write([&] {
                            object_origin2.set_property_value(d, "link", std::any());
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);

                        // remove a backlink
                        write([&] {
                            table_origin->remove_object(object_origin2.get_obj().get_key());
                        });
                        REQUIRE_INDICES(change.modifications, 0);
                        REQUIRE(change.columns.size() == 1);
                        REQUIRE_INDICES(change.columns[col_target_backlink.value], 0);
                    }
                }
            }

            SECTION("deleting the object sends a change notification") {
                auto token = require_change(object_origin, kpa_origin_value);

                write([&] {
                    obj_origin.remove();
                });
                REQUIRE_INDICES(change.deletions, 0);
            }
        }
    }

    SECTION("create object") {
        auto obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(10)}}},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-abba-baba-caca-4136c566a962")},
            {"mixed", "mixed"s},

            {"bool array", AnyVec{true, false}},
            {"int array", AnyVec{INT64_C(5), INT64_C(6)}},
            {"float array", AnyVec{1.1f, 2.2f}},
            {"double array", AnyVec{3.3, 4.4}},
            {"string array", AnyVec{"a"s, "b"s, "c"s}},
            {"data array", AnyVec{"d"s, "e"s, "f"s}},
            {"date array", AnyVec{Timestamp(10, 20), Timestamp(30, 40)}},
            {"object array", AnyVec{AnyDict{{"_id", INT64_C(20)}, {"value", INT64_C(20)}}}},
            {"object id array", AnyVec{ObjectId("AAAAAAAAAAAAAAAAAAAAAAAA"), ObjectId("BBBBBBBBBBBBBBBBBBBBBBBB")}},
            {"decimal array", AnyVec{Decimal128("1.23e45"), Decimal128("6.78e9")}},
            {"uuid array", AnyVec{UUID(), UUID("3b241101-e2bb-4255-8caf-4136c566a962")}},
            {"mixed array",
             AnyVec{25, "b"s, 1.45, util::none, Timestamp(30, 40), Decimal128("1.23e45"),
                    ObjectId("AAAAAAAAAAAAAAAAAAAAAAAA"), UUID("3b241101-e2bb-4255-8caf-4136c566a962")}},
            {"dictionary", AnyDict{{"key", "value"s}}},
        });

        Obj row = obj.get_obj();
        auto link_target = *r->read_group().get_table("class_link target")->begin();
        TableRef table = row.get_table();
        auto target_table = link_target.get_table();
        auto array_target_table = r->read_group().get_table("class_array target");
        REQUIRE(row.get<Int>(table->get_column_key("_id")) == 1);
        REQUIRE(row.get<Bool>(table->get_column_key("bool")) == true);
        REQUIRE(row.get<Int>(table->get_column_key("int")) == 5);
        REQUIRE(row.get<float>(table->get_column_key("float")) == 2.2f);
        REQUIRE(row.get<double>(table->get_column_key("double")) == 3.3);
        REQUIRE(row.get<String>(table->get_column_key("string")) == "hello");
        REQUIRE(row.get<Binary>(table->get_column_key("data")) == BinaryData("olleh", 5));
        REQUIRE(row.get<Timestamp>(table->get_column_key("date")) == Timestamp(10, 20));
        REQUIRE(row.get<ObjKey>(table->get_column_key("object")) == link_target.get_key());
        REQUIRE(row.get<ObjectId>(table->get_column_key("object id")) == ObjectId("000000000000000000000001"));
        REQUIRE(row.get<Decimal128>(table->get_column_key("decimal")) == Decimal128("1.23e45"));
        REQUIRE(row.get<UUID>(table->get_column_key("uuid")) == UUID("3b241101-abba-baba-caca-4136c566a962"));
        REQUIRE(row.get<Mixed>(table->get_column_key("mixed")) == Mixed("mixed"));

        REQUIRE(link_target.get<Int>(target_table->get_column_key("value")) == 10);

        auto check_array = [&](ColKey col, auto... values) {
            auto vec = get_vector({values...});
            using U = typename decltype(vec)::value_type;
            auto list = row.get_list<U>(col);
            size_t i = 0;
            for (auto value : vec) {
                CAPTURE(i);
                REQUIRE(i < list.size());
                REQUIRE(value == list.get(i));
                ++i;
            }
        };
        check_array(table->get_column_key("bool array"), true, false);
        check_array(table->get_column_key("int array"), INT64_C(5), INT64_C(6));
        check_array(table->get_column_key("float array"), 1.1f, 2.2f);
        check_array(table->get_column_key("double array"), 3.3, 4.4);
        check_array(table->get_column_key("string array"), StringData("a"), StringData("b"), StringData("c"));
        check_array(table->get_column_key("data array"), BinaryData("d", 1), BinaryData("e", 1), BinaryData("f", 1));
        check_array(table->get_column_key("date array"), Timestamp(10, 20), Timestamp(30, 40));
        check_array(table->get_column_key("object id array"), ObjectId("AAAAAAAAAAAAAAAAAAAAAAAA"),
                    ObjectId("BBBBBBBBBBBBBBBBBBBBBBBB"));
        check_array(table->get_column_key("decimal array"), Decimal128("1.23e45"), Decimal128("6.78e9"));
        check_array(table->get_column_key("uuid array"), UUID(), UUID("3b241101-e2bb-4255-8caf-4136c566a962"));
        {
            auto list = row.get_list<Mixed>(table->get_column_key("mixed array"));
            REQUIRE(list.size() == 8);
            REQUIRE(list.get(0).get_int() == 25);
            REQUIRE(list.get(1).get_string() == "b");
            REQUIRE(list.get(2).get_double() == 1.45);
            REQUIRE(list.get(3).is_null());
            REQUIRE(list.get(4).get_timestamp() == Timestamp(30, 40));
            REQUIRE(list.get(5).get_decimal() == Decimal128("1.23e45"));
            REQUIRE(list.get(6).get_object_id() == ObjectId("AAAAAAAAAAAAAAAAAAAAAAAA"));
            REQUIRE(list.get(7).get_uuid() == UUID("3b241101-e2bb-4255-8caf-4136c566a962"));
        }

        REQUIRE(row.get_dictionary(table->get_column_key("dictionary")).get("key") == Mixed("value"));

        auto list = row.get_linklist_ptr(table->get_column_key("object array"));
        REQUIRE(list->size() == 1);
        REQUIRE(list->get_object(0).get<Int>(array_target_table->get_column_key("value")) == 20);
    }

    SECTION("create uses defaults for missing values") {
        d.defaults["all types"] = {
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(10)}}},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-1111-2222-3333-4136c566a962")},

            {"bool array", AnyVec{true, false}},
            {"int array", AnyVec{INT64_C(5), INT64_C(6)}},
            {"float array", AnyVec{1.1f, 2.2f}},
            {"double array", AnyVec{3.3, 4.4}},
            {"string array", AnyVec{"a"s, "b"s, "c"s}},
            {"data array", AnyVec{"d"s, "e"s, "f"s}},
            {"date array", AnyVec{}},
            {"object array", AnyVec{AnyDict{{"_id", INT64_C(20)}, {"value", INT64_C(20)}}}},
            {"object id array", AnyVec{ObjectId("AAAAAAAAAAAAAAAAAAAAAAAA"), ObjectId("BBBBBBBBBBBBBBBBBBBBBBBB")}},
            {"decimal array", AnyVec{Decimal128("1.23e45"), Decimal128("6.78e9")}},
            {"uuid array", AnyVec{UUID(), UUID("3b241101-e2bb-4255-8caf-4136c566a962")}},
            {"dictionary", AnyDict{{"name", "John Doe"s}}},
        };

        Object obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"float", 6.6f},
        });

        Obj row = obj.get_obj();
        TableRef table = row.get_table();
        REQUIRE(row.get<Int>(table->get_column_key("_id")) == 1);
        REQUIRE(row.get<Bool>(table->get_column_key("bool")) == true);
        REQUIRE(row.get<Int>(table->get_column_key("int")) == 5);
        REQUIRE(row.get<float>(table->get_column_key("float")) == 6.6f);
        REQUIRE(row.get<double>(table->get_column_key("double")) == 3.3);
        REQUIRE(row.get<String>(table->get_column_key("string")) == "hello");
        REQUIRE(row.get<Binary>(table->get_column_key("data")) == BinaryData("olleh", 5));
        REQUIRE(row.get<Timestamp>(table->get_column_key("date")) == Timestamp(10, 20));
        REQUIRE(row.get<ObjectId>(table->get_column_key("object id")) == ObjectId("000000000000000000000001"));
        REQUIRE(row.get<Decimal128>(table->get_column_key("decimal")) == Decimal128("1.23e45"));
        REQUIRE(row.get<UUID>(table->get_column_key("uuid")) == UUID("3b241101-1111-2222-3333-4136c566a962"));
        REQUIRE(row.get_dictionary(table->get_column_key("dictionary")).get("name") == Mixed("John Doe"));

        REQUIRE(row.get_listbase_ptr(table->get_column_key("bool array"))->size() == 2);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("int array"))->size() == 2);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("float array"))->size() == 2);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("double array"))->size() == 2);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("string array"))->size() == 3);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("data array"))->size() == 3);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("date array"))->size() == 0);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("object array"))->size() == 1);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("object id array"))->size() == 2);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("decimal array"))->size() == 2);
        REQUIRE(row.get_listbase_ptr(table->get_column_key("uuid array"))->size() == 2);
    }

    SECTION("create can use defaults for primary key") {
        d.defaults["all types"] = {
            {"_id", INT64_C(10)},
        };
        auto obj = create(AnyDict{
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(10)}}},
            {"array", AnyVector{AnyDict{{"value", INT64_C(20)}}}},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-0000-0000-0000-4136c566a962")},
            {"dictionary", AnyDict{{"key", "value"s}}},
        });

        auto row = obj.get_obj();
        REQUIRE(row.get<Int>(row.get_table()->get_column_key("_id")) == 10);
    }

    SECTION("create does not complain about missing values for nullable fields") {
        r->begin_transaction();
        realm::Object obj;
        REQUIRE_NOTHROW(obj = Object::create(d, r, *r->schema().find("all optional types"), std::any(AnyDict{})));
        r->commit_transaction();

        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "_id").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "bool").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "int").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "float").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "double").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "string").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "data").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "date").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "object id").has_value());
        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "uuid").has_value());

        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "bool array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "int array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "float array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "double array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "string array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "data array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "date array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "object id array")).size() == 0);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "uuid array")).size() == 0);
    }

    SECTION("create throws for missing values if there is no default") {
        REQUIRE_EXCEPTION(create(AnyDict{{"_id", INT64_C(1)}, {"float", 6.6f}}), MissingPropertyValue,
                          "Missing value for property 'all types.bool'");
    }

    SECTION("create always sets the PK first") {
        AnyDict value{
            {"array 1", AnyVector{AnyDict{{"_id", INT64_C(1)}, {"value", INT64_C(1)}}}},
            {"array 2", AnyVector{AnyDict{{"_id", INT64_C(2)}, {"value", INT64_C(2)}}}},
            {"int 1", INT64_C(0)},
            {"int 2", INT64_C(0)},
            {"_id", INT64_C(7)},
        };
        // Core will throw if the list is populated before the PK is set
        r->begin_transaction();
        REQUIRE_NOTHROW(Object::create(d, r, *r->schema().find("pk after list"), std::any(value)));
    }

    SECTION("create with update") {
        CollectionChangeSet change;
        bool callback_called;
        Object obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(10)}}},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-9999-9999-9999-4136c566a962")},
            {"dictionary", AnyDict{{"key", "value"s}}},

            {"bool array", AnyVec{true, false}},
            {"int array", AnyVec{INT64_C(5), INT64_C(6)}},
            {"float array", AnyVec{1.1f, 2.2f}},
            {"double array", AnyVec{3.3, 4.4}},
            {"string array", AnyVec{"a"s, "b"s, "c"s}},
            {"data array", AnyVec{"d"s, "e"s, "f"s}},
            {"date array", AnyVec{}},
            {"object array", AnyVec{AnyDict{{"_id", INT64_C(20)}, {"value", INT64_C(20)}}}},
            {"object id array", AnyVec{ObjectId("AAAAAAAAAAAAAAAAAAAAAAAA"), ObjectId("BBBBBBBBBBBBBBBBBBBBBBBB")}},
            {"decimal array", AnyVec{Decimal128("1.23e45"), Decimal128("6.78e9")}},
            {"uuid array", AnyVec{UUID(), UUID("3b241101-1234-5678-9012-4136c566a962")}}});

        auto token = obj.add_notification_callback([&](CollectionChangeSet c) {
            change = c;
            callback_called = true;
        });
        advance_and_notify(*r);

        create(
            AnyDict{
                {"_id", INT64_C(1)},
                {"int", INT64_C(6)},
                {"string", "a"s},
            },
            CreatePolicy::UpdateAll);

        callback_called = false;
        advance_and_notify(*r);
        REQUIRE(callback_called);
        REQUIRE_INDICES(change.modifications, 0);

        auto row = obj.get_obj();
        auto table = row.get_table();
        REQUIRE(row.get<Int>(table->get_column_key("_id")) == 1);
        REQUIRE(row.get<Bool>(table->get_column_key("bool")) == true);
        REQUIRE(row.get<Int>(table->get_column_key("int")) == 6);
        REQUIRE(row.get<float>(table->get_column_key("float")) == 2.2f);
        REQUIRE(row.get<double>(table->get_column_key("double")) == 3.3);
        REQUIRE(row.get<String>(table->get_column_key("string")) == "a");
        REQUIRE(row.get<Binary>(table->get_column_key("data")) == BinaryData("olleh", 5));
        REQUIRE(row.get<Timestamp>(table->get_column_key("date")) == Timestamp(10, 20));
        REQUIRE(row.get<ObjectId>(table->get_column_key("object id")) == ObjectId("000000000000000000000001"));
        REQUIRE(row.get<Decimal128>(table->get_column_key("decimal")) == Decimal128("1.23e45"));
        REQUIRE(row.get<UUID>(table->get_column_key("uuid")) == UUID("3b241101-9999-9999-9999-4136c566a962"));
    }

    SECTION("create with update - only with diffs") {
        CollectionChangeSet change;
        bool callback_called;
        AnyDict adam{
            {"_id", "pk0"s},
            {"name", "Adam"s},
            {"age", INT64_C(32)},
            {"scores", AnyVec{INT64_C(1), INT64_C(2)}},
        };
        AnyDict brian{
            {"_id", "pk1"s},
            {"name", "Brian"s},
            {"age", INT64_C(33)},
        };
        AnyDict charley{{"_id", "pk2"s}, {"name", "Charley"s}, {"age", INT64_C(34)}, {"team", AnyVec{adam, brian}}};
        AnyDict donald{
            {"_id", "pk3"s},
            {"name", "Donald"s},
            {"age", INT64_C(35)},
        };
        AnyDict eddie{{"_id", "pk4"s},
                      {"name", "Eddie"s},
                      {"age", INT64_C(36)},
                      {"assistant", donald},
                      {"team", AnyVec{donald, charley}}};
        Object obj = create_company(eddie, CreatePolicy::UpdateAll);

        auto table = r->read_group().get_table("class_person");
        REQUIRE(table->size() == 5);
        Results result(r, table);
        result = result.sort({{"_id", false}});
        auto token = result.add_notification_callback([&](CollectionChangeSet c) {
            change = c;
            callback_called = true;
        });
        advance_and_notify(*r);

        // First update unconditionally
        create_company(eddie, CreatePolicy::UpdateAll);

        callback_called = false;
        advance_and_notify(*r);
        REQUIRE(callback_called);
        REQUIRE_INDICES(change.modifications, 0, 1, 2, 3, 4);

        // Now, only update where differences (there should not be any diffs - so no update)
        create_company(eddie, CreatePolicy::UpdateModified);

        REQUIRE(table->size() == 5);
        callback_called = false;
        advance_and_notify(*r);
        REQUIRE(!callback_called);

        // Now, only update sub-object)
        donald["scores"] = AnyVec{INT64_C(3), INT64_C(4), INT64_C(5)};
        // Insert the new donald
        eddie["assistant"] = donald;
        create_company(eddie, CreatePolicy::UpdateModified);

        REQUIRE(table->size() == 5);
        callback_called = false;
        advance_and_notify(*r);
        REQUIRE(callback_called);
        REQUIRE_INDICES(change.modifications, 1);

        // Shorten list
        donald["scores"] = AnyVec{INT64_C(3), INT64_C(4)};
        eddie["assistant"] = donald;
        create_company(eddie, CreatePolicy::UpdateModified);

        REQUIRE(table->size() == 5);
        callback_called = false;
        advance_and_notify(*r);
        REQUIRE(callback_called);
        REQUIRE_INDICES(change.modifications, 1);
    }

    SECTION("create with update - identical sub-object") {
        Object sub_obj = create_sub(AnyDict{{"value", INT64_C(10)}, {"_id", INT64_C(10)}});
        Object obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object", sub_obj},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-9999-9999-9999-4136c566a962")},
            {"dictionary", AnyDict{{"key", "value"s}}},
        });

        auto obj_table = r->read_group().get_table("class_all types");
        Results result(r, obj_table);
        bool callback_called;
        bool results_callback_called;
        bool sub_callback_called;
        auto token1 = obj.add_notification_callback([&](CollectionChangeSet) {
            callback_called = true;
        });
        auto token2 = result.add_notification_callback([&](CollectionChangeSet) {
            results_callback_called = true;
        });
        auto token3 = sub_obj.add_notification_callback([&](CollectionChangeSet) {
            sub_callback_called = true;
        });
        advance_and_notify(*r);

        auto table = r->read_group().get_table("class_link target");
        REQUIRE(table->size() == 1);

        create(
            AnyDict{
                {"_id", INT64_C(1)},
                {"bool", true},
                {"int", INT64_C(5)},
                {"float", 2.2f},
                {"double", 3.3},
                {"string", "hello"s},
                {"data", "olleh"s},
                {"date", Timestamp(10, 20)},
                {"object id", ObjectId("000000000000000000000001")},
                {"decimal", Decimal128("1.23e45")},
                {"uuid", UUID("3b241101-9999-9999-9999-4136c566a962")},
                {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(10)}}},
            },
            CreatePolicy::UpdateModified);

        REQUIRE(table->size() == 1);
        callback_called = false;
        results_callback_called = false;
        sub_callback_called = false;
        advance_and_notify(*r);
        REQUIRE(!callback_called);
        REQUIRE(!results_callback_called);
        REQUIRE(!sub_callback_called);

        // Now change sub object
        create(
            AnyDict{
                {"_id", INT64_C(1)},
                {"bool", true},
                {"int", INT64_C(5)},
                {"float", 2.2f},
                {"double", 3.3},
                {"string", "hello"s},
                {"data", "olleh"s},
                {"date", Timestamp(10, 20)},
                {"object id", ObjectId("000000000000000000000001")},
                {"decimal", Decimal128("1.23e45")},
                {"uuid", UUID("3b241101-9999-9999-9999-4136c566a962")},
                {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(11)}}},
            },
            CreatePolicy::UpdateModified);

        callback_called = false;
        results_callback_called = false;
        sub_callback_called = false;
        advance_and_notify(*r);
        REQUIRE(!callback_called);
        REQUIRE(results_callback_called);
        REQUIRE(sub_callback_called);
    }

    SECTION("create with update - identical array of sub-objects") {
        bool callback_called;
        auto dict = AnyDict{
            {"_id", INT64_C(1)},
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object array", AnyVec{AnyDict{{"_id", INT64_C(20)}, {"value", INT64_C(20)}},
                                    AnyDict{{"_id", INT64_C(21)}, {"value", INT64_C(21)}}}},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-aaaa-bbbb-cccc-4136c566a962")},
            {"dictionary", AnyDict{{"key", "value"s}}},
        };
        Object obj = create(dict);

        auto obj_table = r->read_group().get_table("class_all types");
        Results result(r, obj_table);
        auto token1 = result.add_notification_callback([&](CollectionChangeSet) {
            callback_called = true;
        });
        advance_and_notify(*r);

        create(dict, CreatePolicy::UpdateModified);

        callback_called = false;
        advance_and_notify(*r);
        REQUIRE(!callback_called);

        // Now change list
        dict["object array"] = AnyVec{AnyDict{{"_id", INT64_C(23)}, {"value", INT64_C(23)}}};
        create(dict, CreatePolicy::UpdateModified);

        callback_called = false;
        advance_and_notify(*r);
        REQUIRE(callback_called);
    }

    for (auto policy : {CreatePolicy::UpdateAll, CreatePolicy::UpdateModified}) {
        SECTION("set existing fields to null with update "s + (policy.diff ? "(diffed)" : "(all)")) {
            AnyDict initial_values{
                {"_id", INT64_C(1)},
                {"bool", true},
                {"int", INT64_C(5)},
                {"float", 2.2f},
                {"double", 3.3},
                {"string", "hello"s},
                {"data", "olleh"s},
                {"date", Timestamp(10, 20)},
                {"object id", ObjectId("000000000000000000000001")},
                {"decimal", Decimal128("1.23e45")},
                {"uuid", UUID("3b241101-aaaa-bbbb-cccc-4136c566a962")},

                {"bool array", AnyVec{true, false}},
                {"int array", AnyVec{INT64_C(5), INT64_C(6)}},
                {"float array", AnyVec{1.1f, 2.2f}},
                {"double array", AnyVec{3.3, 4.4}},
                {"string array", AnyVec{"a"s, "b"s, "c"s}},
                {"data array", AnyVec{"d"s, "e"s, "f"s}},
                {"date array", AnyVec{}},
                {"object array", AnyVec{AnyDict{{"_id", INT64_C(20)}, {"value", INT64_C(20)}}}},
                {"object id array", AnyVec{ObjectId("000000000000000000000001")}},
                {"decimal array", AnyVec{Decimal128("1.23e45")}},
                {"uuid array", AnyVec{UUID("3b241101-1111-bbbb-cccc-4136c566a962")}},
            };
            r->begin_transaction();
            auto obj = Object::create(d, r, *r->schema().find("all optional types"), std::any(initial_values));

            // Missing fields in dictionary do not update anything
            Object::create(d, r, *r->schema().find("all optional types"), std::any(AnyDict{{"_id", INT64_C(1)}}),
                           policy);

            REQUIRE(d.get<bool>(obj, "bool") == true);
            REQUIRE(d.get<int64_t>(obj, "int") == 5);
            REQUIRE(d.get<float>(obj, "float") == 2.2f);
            REQUIRE(d.get<double>(obj, "double") == 3.3);
            REQUIRE(d.get<std::string>(obj, "string") == "hello");
            REQUIRE(d.get<Timestamp>(obj, "date") == Timestamp(10, 20));
            REQUIRE(d.get<util::Optional<ObjectId>>(obj, "object id") == ObjectId("000000000000000000000001"));
            REQUIRE(d.get<Decimal128>(obj, "decimal") == Decimal128("1.23e45"));
            REQUIRE(d.get<util::Optional<UUID>>(obj, "uuid") == UUID("3b241101-aaaa-bbbb-cccc-4136c566a962"));

            REQUIRE(d.get<List>(obj, "bool array").get<util::Optional<bool>>(0) == true);
            REQUIRE(d.get<List>(obj, "int array").get<util::Optional<int64_t>>(0) == 5);
            REQUIRE(d.get<List>(obj, "float array").get<util::Optional<float>>(0) == 1.1f);
            REQUIRE(d.get<List>(obj, "double array").get<util::Optional<double>>(0) == 3.3);
            REQUIRE(d.get<List>(obj, "string array").get<StringData>(0) == "a");
            REQUIRE(d.get<List>(obj, "date array").size() == 0);
            REQUIRE(d.get<List>(obj, "object id array").get<util::Optional<ObjectId>>(0) ==
                    ObjectId("000000000000000000000001"));
            REQUIRE(d.get<List>(obj, "decimal array").get<Decimal128>(0) == Decimal128("1.23e45"));
            REQUIRE(d.get<List>(obj, "uuid array").get<util::Optional<UUID>>(0) ==
                    UUID("3b241101-1111-bbbb-cccc-4136c566a962"));

            // Set all properties to null
            AnyDict null_values{
                {"_id", INT64_C(1)},
                {"bool", std::any()},
                {"int", std::any()},
                {"float", std::any()},
                {"double", std::any()},
                {"string", std::any()},
                {"data", std::any()},
                {"date", std::any()},
                {"object id", std::any()},
                {"decimal", std::any()},
                {"uuid", std::any()},

                {"bool array", AnyVec{std::any()}},
                {"int array", AnyVec{std::any()}},
                {"float array", AnyVec{std::any()}},
                {"double array", AnyVec{std::any()}},
                {"string array", AnyVec{std::any()}},
                {"data array", AnyVec{std::any()}},
                {"date array", AnyVec{Timestamp()}},
                {"object id array", AnyVec{std::any()}},
                {"decimal array", AnyVec{Decimal128(realm::null())}},
                {"uuid array", AnyVec{std::any()}},
            };
            Object::create(d, r, *r->schema().find("all optional types"), std::any(null_values), policy);

            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "bool").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "int").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "float").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "double").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "string").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "data").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "date").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "object id").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "decimal").has_value());
            REQUIRE_FALSE(obj.get_property_value<std::any>(d, "uuid").has_value());

            REQUIRE(d.get<List>(obj, "bool array").get<util::Optional<bool>>(0) == util::none);
            REQUIRE(d.get<List>(obj, "int array").get<util::Optional<int64_t>>(0) == util::none);
            REQUIRE(d.get<List>(obj, "float array").get<util::Optional<float>>(0) == util::none);
            REQUIRE(d.get<List>(obj, "double array").get<util::Optional<double>>(0) == util::none);
            REQUIRE(d.get<List>(obj, "string array").get<StringData>(0) == StringData());
            REQUIRE(d.get<List>(obj, "data array").get<BinaryData>(0) == BinaryData());
            REQUIRE(d.get<List>(obj, "date array").get<Timestamp>(0) == Timestamp());
            REQUIRE(d.get<List>(obj, "object id array").get<util::Optional<ObjectId>>(0) == util::none);
            REQUIRE(d.get<List>(obj, "decimal array").get<Decimal>(0) == Decimal128(realm::null()));
            REQUIRE(d.get<List>(obj, "uuid array").get<util::Optional<UUID>>(0) == util::none);

            // Set all lists to null
            AnyDict null_arrays{
                {"_id", INT64_C(1)},           {"bool array", std::any()},   {"int array", std::any()},
                {"float array", std::any()},   {"double array", std::any()}, {"string array", std::any()},
                {"data array", std::any()},    {"date array", std::any()},   {"object id array", std::any()},
                {"decimal array", std::any()}, {"uuid array", std::any()}};
            Object::create(d, r, *r->schema().find("all optional types"), std::any(null_arrays), policy);

            REQUIRE(d.get<List>(obj, "bool array").size() == 0);
            REQUIRE(d.get<List>(obj, "int array").size() == 0);
            REQUIRE(d.get<List>(obj, "float array").size() == 0);
            REQUIRE(d.get<List>(obj, "double array").size() == 0);
            REQUIRE(d.get<List>(obj, "string array").size() == 0);
            REQUIRE(d.get<List>(obj, "data array").size() == 0);
            REQUIRE(d.get<List>(obj, "date array").size() == 0);
            REQUIRE(d.get<List>(obj, "object id array").size() == 0);
            REQUIRE(d.get<List>(obj, "decimal array").size() == 0);
            REQUIRE(d.get<List>(obj, "uuid array").size() == 0);

            // Set all properties back to non-null
            Object::create(d, r, *r->schema().find("all optional types"), std::any(initial_values), policy);
            REQUIRE(d.get<bool>(obj, "bool") == true);
            REQUIRE(d.get<int64_t>(obj, "int") == 5);
            REQUIRE(d.get<float>(obj, "float") == 2.2f);
            REQUIRE(d.get<double>(obj, "double") == 3.3);
            REQUIRE(d.get<std::string>(obj, "string") == "hello");
            REQUIRE(d.get<Timestamp>(obj, "date") == Timestamp(10, 20));
            REQUIRE(d.get<util::Optional<ObjectId>>(obj, "object id").value() ==
                    ObjectId("000000000000000000000001"));
            REQUIRE(d.get<Decimal128>(obj, "decimal") == Decimal128("1.23e45"));
            REQUIRE(d.get<util::Optional<UUID>>(obj, "uuid") == UUID("3b241101-aaaa-bbbb-cccc-4136c566a962"));

            REQUIRE(d.get<List>(obj, "bool array").get<util::Optional<bool>>(0) == true);
            REQUIRE(d.get<List>(obj, "int array").get<util::Optional<int64_t>>(0) == 5);
            REQUIRE(d.get<List>(obj, "float array").get<util::Optional<float>>(0) == 1.1f);
            REQUIRE(d.get<List>(obj, "double array").get<util::Optional<double>>(0) == 3.3);
            REQUIRE(d.get<List>(obj, "string array").get<StringData>(0) == "a");
            REQUIRE(d.get<List>(obj, "date array").size() == 0);
            REQUIRE(d.get<List>(obj, "object id array").get<util::Optional<ObjectId>>(0) ==
                    ObjectId("000000000000000000000001"));
            REQUIRE(d.get<List>(obj, "decimal array").get<Decimal128>(0) == Decimal128("1.23e45"));
            REQUIRE(d.get<List>(obj, "uuid array").get<util::Optional<UUID>>(0) ==
                    UUID("3b241101-1111-bbbb-cccc-4136c566a962"));
        }
    }

    SECTION("create throws for duplicate pk if update is not specified") {
        create(AnyDict{
            {"_id", INT64_C(1)},
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(10)}}},
            {"array", AnyVector{AnyDict{{"value", INT64_C(20)}}}},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-aaaa-bbbb-cccc-4136c566a962")},
            {"dictionary", AnyDict{{"key", "value"s}}},
        });
        REQUIRE_EXCEPTION(create(AnyDict{
                              {"_id", INT64_C(1)},
                              {"bool", true},
                              {"int", INT64_C(5)},
                              {"float", 2.2f},
                              {"double", 3.3},
                              {"string", "hello"s},
                              {"data", "olleh"s},
                              {"date", Timestamp(10, 20)},
                              {"object", AnyDict{{"_id", INT64_C(10)}, {"value", INT64_C(10)}}},
                              {"array", AnyVector{AnyDict{{"value", INT64_C(20)}}}},
                              {"object id", ObjectId("000000000000000000000001")},
                              {"decimal", Decimal128("1.23e45")},
                              {"uuid", UUID("3b241101-aaaa-bbbb-cccc-4136c566a962")},
                              {"dictionary", AnyDict{{"key", "value"s}}},
                          }),
                          ObjectAlreadyExists,
                          "Attempting to create an object of type 'all types' with an existing primary key value "
                          "'not implemented'");
    }

    SECTION("create with explicit null pk does not fall back to default") {
        d.defaults["nullable int pk"] = {
            {"_id", INT64_C(10)},
        };
        d.defaults["nullable string pk"] = {
            {"_id", "value"s},
        };
        auto create = [&](std::any&& value, StringData type) {
            r->begin_transaction();
            auto obj = Object::create(d, r, *r->schema().find(type), value);
            r->commit_transaction();
            return obj;
        };

        auto obj = create(AnyDict{{"_id", d.null_value()}}, "nullable int pk");
        auto col_pk_int = r->read_group().get_table("class_nullable int pk")->get_column_key("_id");
        auto col_pk_str = r->read_group().get_table("class_nullable string pk")->get_column_key("_id");
        REQUIRE(obj.get_obj().is_null(col_pk_int));
        obj = create(AnyDict{{"_id", d.null_value()}}, "nullable string pk");
        REQUIRE(obj.get_obj().is_null(col_pk_str));

        obj = create(AnyDict{{}}, "nullable int pk");
        REQUIRE(obj.get_obj().get<util::Optional<Int>>(col_pk_int) == 10);
        obj = create(AnyDict{{}}, "nullable string pk");
        REQUIRE(obj.get_obj().get<String>(col_pk_str) == "value");
    }

    SECTION("create null and 0 primary keys for Int types") {
        auto create = [&](std::any&& value, StringData type) {
            r->begin_transaction();
            auto obj = Object::create(d, r, *r->schema().find(type), value);
            r->commit_transaction();
            return obj;
        };
        create(AnyDict{{"_id", std::any()}}, "all optional types");
        create(AnyDict{{"_id", INT64_C(0)}}, "all optional types");
        REQUIRE(Results(r, r->read_group().get_table("class_all optional types")).size() == 2);
    }

    SECTION("create null and default primary keys for ObjectId types") {
        auto create = [&](std::any&& value, StringData type) {
            r->begin_transaction();
            auto obj = Object::create(d, r, *r->schema().find(type), value);
            r->commit_transaction();
            return obj;
        };
        create(AnyDict{{"_id", std::any()}}, "nullable object id pk");
        create(AnyDict{{"_id", ObjectId::gen()}}, "nullable object id pk");
        REQUIRE(Results(r, r->read_group().get_table("class_nullable object id pk")).size() == 2);
    }

    SECTION("create only requires properties explicitly in the schema") {
        config.schema = Schema{{"all types", {{"_id", PropertyType::Int, Property::IsPrimary{true}}}}};
        auto subset_realm = Realm::get_shared_realm(config);
        subset_realm->begin_transaction();
        REQUIRE_NOTHROW(Object::create(d, subset_realm, "all types", std::any(AnyDict{{"_id", INT64_C(123)}})));
        subset_realm->commit_transaction();

        r->refresh();
        auto obj = *r->read_group().get_table("class_all types")->begin();
        REQUIRE(obj.get<int64_t>("_id") == 123);

        // Other columns should have the default unset values
        REQUIRE(obj.get<bool>("bool") == false);
        REQUIRE(obj.get<int64_t>("int") == 0);
        REQUIRE(obj.get<float>("float") == 0);
        REQUIRE(obj.get<StringData>("string") == "");
    }

    SECTION("getters and setters") {
        r->begin_transaction();

        auto table = r->read_group().get_table("class_all types");
        table->create_object_with_primary_key(1);
        Object obj(r, *r->schema().find("all types"), *table->begin());

        auto link_table = r->read_group().get_table("class_link target");
        link_table->create_object_with_primary_key(0);
        Object linkobj(r, *r->schema().find("link target"), *link_table->begin());

        auto property = *r->schema().find("all types")->property_for_name("int");
        obj.set_property_value(d, property, std::any(INT64_C(6)));
        REQUIRE(util::any_cast<int64_t>(obj.get_property_value<std::any>(d, property)) == 6);

        obj.set_property_value(d, "bool", std::any(true));
        REQUIRE(util::any_cast<bool>(obj.get_property_value<std::any>(d, "bool")) == true);

        obj.set_property_value(d, "int", std::any(INT64_C(5)));
        REQUIRE(util::any_cast<int64_t>(obj.get_property_value<std::any>(d, "int")) == 5);

        obj.set_property_value(d, "float", std::any(1.23f));
        REQUIRE(util::any_cast<float>(obj.get_property_value<std::any>(d, "float")) == 1.23f);

        obj.set_property_value(d, "double", std::any(1.23));
        REQUIRE(util::any_cast<double>(obj.get_property_value<std::any>(d, "double")) == 1.23);

        obj.set_property_value(d, "string", std::any("abc"s));
        REQUIRE(util::any_cast<std::string>(obj.get_property_value<std::any>(d, "string")) == "abc");

        obj.set_property_value(d, "data", std::any("abc"s));
        REQUIRE(util::any_cast<std::string>(obj.get_property_value<std::any>(d, "data")) == "abc");

        obj.set_property_value(d, "date", std::any(Timestamp(1, 2)));
        REQUIRE(util::any_cast<Timestamp>(obj.get_property_value<std::any>(d, "date")) == Timestamp(1, 2));

        obj.set_property_value(d, "object id", std::any(ObjectId("111111111111111111111111")));
        REQUIRE(util::any_cast<ObjectId>(obj.get_property_value<std::any>(d, "object id")) ==
                ObjectId("111111111111111111111111"));

        obj.set_property_value(d, "decimal", std::any(Decimal128("42.4242e42")));
        REQUIRE(util::any_cast<Decimal128>(obj.get_property_value<std::any>(d, "decimal")) ==
                Decimal128("42.4242e42"));

        obj.set_property_value(d, "uuid", std::any(UUID("3b241101-aaaa-bbbb-cccc-4136c566a962")));
        REQUIRE(util::any_cast<UUID>(obj.get_property_value<std::any>(d, "uuid")) ==
                UUID("3b241101-aaaa-bbbb-cccc-4136c566a962"));

        obj.set_property_value(d, "mixed", std::any(25));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) == 25);
        obj.set_property_value(d, "mixed", std::any("Hello"s));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) == "Hello");
        obj.set_property_value(d, "mixed", std::any(1.23));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) == 1.23);
        obj.set_property_value(d, "mixed", std::any(123.45f));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) == 123.45f);
        obj.set_property_value(d, "mixed", std::any(Timestamp(30, 40)));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) == Timestamp(30, 40));
        obj.set_property_value(d, "mixed", std::any(ObjectId("111111111111111111111111")));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) ==
                ObjectId("111111111111111111111111"));
        obj.set_property_value(d, "mixed", std::any(Decimal128("42.4242e42")));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) == Decimal128("42.4242e42"));
        obj.set_property_value(d, "mixed", std::any(UUID("3b241101-aaaa-bbbb-cccc-4136c566a962")));
        REQUIRE(util::any_cast<Mixed>(obj.get_property_value<std::any>(d, "mixed")) ==
                UUID("3b241101-aaaa-bbbb-cccc-4136c566a962"));

        obj.set_property_value(d, "dictionary", std::any(AnyDict({{"k1", "v1"s}, {"k2", "v2"s}})));
        auto dict = util::any_cast<object_store::Dictionary&&>(obj.get_property_value<std::any>(d, "dictionary"));
        REQUIRE(dict.get_any("k1") == "v1");
        REQUIRE(dict.get_any("k2") == "v2");

        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "object").has_value());
        obj.set_property_value(d, "object", std::any(linkobj));
        REQUIRE(util::any_cast<Object>(obj.get_property_value<std::any>(d, "object")).get_obj().get_key() ==
                linkobj.get_obj().get_key());

        auto linking = util::any_cast<Results>(linkobj.get_property_value<std::any>(d, "origin"));
        REQUIRE(linking.size() == 1);

        REQUIRE_EXCEPTION(obj.set_property_value(d, "_id", std::any(INT64_C(5))), ModifyPrimaryKey,
                          "Cannot modify primary key after creation: 'all types._id'");
        REQUIRE_EXCEPTION(obj.set_property_value(d, "not a property", std::any(INT64_C(5))), InvalidProperty,
                          "Property 'all types.not a property' does not exist");

        r->commit_transaction();

        REQUIRE_EXCEPTION(obj.get_property_value<std::any>(d, "not a property"), InvalidProperty,
                          "Property 'all types.not a property' does not exist");
        REQUIRE_EXCEPTION(obj.set_property_value(d, "int", std::any(INT64_C(5))), WrongTransactionState,
                          "Cannot modify managed objects outside of a write transaction.");
    }

    SECTION("setter has correct create policy") {
        r->begin_transaction();
        auto table = r->read_group().get_table("class_all types");
        table->create_object_with_primary_key(1);
        Object obj(r, *r->schema().find("all types"), *table->begin());
        CreatePolicyRecordingContext ctx;

        auto validate = [&obj, &ctx](CreatePolicy policy) {
            obj.set_property_value(ctx, "mixed", std::any(Mixed("Hello")), policy);
            REQUIRE(policy.copy == ctx.last_create_policy.copy);
            REQUIRE(policy.diff == ctx.last_create_policy.diff);
            REQUIRE(policy.create == ctx.last_create_policy.create);
            REQUIRE(policy.update == ctx.last_create_policy.update);
        };

        validate(CreatePolicy::Skip);
        validate(CreatePolicy::ForceCreate);
        validate(CreatePolicy::UpdateAll);
        validate(CreatePolicy::UpdateModified);
        validate(CreatePolicy::SetLink);
        r->commit_transaction();
    }

    SECTION("list property self-assign is a no-op") {
        auto obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"bool", true},
            {"int", INT64_C(5)},
            {"float", 2.2f},
            {"double", 3.3},
            {"string", "hello"s},
            {"data", "olleh"s},
            {"date", Timestamp(10, 20)},
            {"object id", ObjectId("000000000000000000000001")},
            {"decimal", Decimal128("1.23e45")},
            {"uuid", UUID("3b241101-aaaa-bbbb-cccc-4136c566a962")},
            {"dictionary", AnyDict{{"key", "value"s}}},

            {"bool array", AnyVec{true, false}},
            {"object array", AnyVec{AnyDict{{"_id", INT64_C(20)}, {"value", INT64_C(20)}}}},
        });

        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "bool array")).size() == 2);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "object array")).size() == 1);

        r->begin_transaction();
        obj.set_property_value(d, "bool array", obj.get_property_value<std::any>(d, "bool array"));
        obj.set_property_value(d, "object array", obj.get_property_value<std::any>(d, "object array"));
        r->commit_transaction();

        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "bool array")).size() == 2);
        REQUIRE(util::any_cast<List&&>(obj.get_property_value<std::any>(d, "object array")).size() == 1);
    }

    SECTION("Mixed emit notification on type change") {
        auto validate_change = [&](std::any&& obj_dict, std::any&& value) {
            r->begin_transaction();
            auto obj =
                Object::create(d, r, *r->schema().find("all optional types"), obj_dict, CreatePolicy::UpdateModified);
            r->commit_transaction();

            CollectionChangeSet change;
            auto token = obj.add_notification_callback([&](CollectionChangeSet c) {
                change = c;
            });
            advance_and_notify(*r);

            r->begin_transaction();
            obj.set_property_value(d, "mixed", value, CreatePolicy::UpdateModified);
            r->commit_transaction();

            advance_and_notify(*r);

            REQUIRE_INDICES(change.modifications, 0);
        };

        validate_change(AnyDict{{"_id", std::any()}, {"mixed", true}}, std::any(1));

        validate_change(AnyDict{{"_id", std::any()}, {"mixed", false}}, std::any(0));

        auto object_id = ObjectId::gen();

        validate_change(AnyDict{{"_id", std::any()}, {"mixed", object_id}}, std::any(object_id.get_timestamp()));
    }

    SECTION("get and set an unresolved object") {
        r->begin_transaction();

        auto table = r->read_group().get_table("class_all types");
        ColKey link_col = table->get_column_key("object");
        table->create_object_with_primary_key(1);
        Object obj(r, *r->schema().find("all types"), *table->begin());

        auto link_table = r->read_group().get_table("class_link target");
        link_table->create_object_with_primary_key(0);
        Object linkobj(r, *r->schema().find("link target"), *link_table->begin());

        REQUIRE_FALSE(obj.get_property_value<std::any>(d, "object").has_value());
        obj.set_property_value(d, "object", std::any(linkobj));
        REQUIRE(util::any_cast<Object>(obj.get_property_value<std::any>(d, "object")).get_obj().get_key() ==
                linkobj.get_obj().get_key());

        REQUIRE(!obj.get_obj().is_unresolved(link_col));
        linkobj.get_obj().invalidate();
        REQUIRE(obj.get_obj().is_unresolved(link_col));

        CHECK_FALSE(obj.get_property_value<std::any>(d, "object").has_value());

        obj.set_property_value(d, "object", std::any());
        // Cancelling a transaction in which the first tombstone was created, caused the program to crash
        // because we tried to update m_tombstones on a null ref. Now fixed
        r->cancel_transaction();
    }

#if REALM_ENABLE_SYNC
    if (!util::EventLoop::has_implementation())
        return;
    SECTION("defaults do not override values explicitly passed to create()") {
        TestSyncManager init_sync_manager({}, {false});
        auto& server = init_sync_manager.sync_server();
        SyncTestFile config1(init_sync_manager, "shared");
        config1.schema = config.schema;
        SyncTestFile config2(init_sync_manager, "shared");
        config2.schema = config.schema;

        AnyDict v1{
            {"_id", INT64_C(7)},
            {"array 1", AnyVector{AnyDict{{"_id", INT64_C(1)}, {"value", INT64_C(1)}}}},
            {"array 2", AnyVector{AnyDict{{"_id", INT64_C(2)}, {"value", INT64_C(2)}}}},
        };
        auto v2 = v1;
        v1["int 1"] = INT64_C(1);
        v2["int 2"] = INT64_C(2);
        v2["array 1"] = AnyVector{AnyDict{{"_id", INT64_C(3)}, {"value", INT64_C(1)}}};
        v2["array 2"] = AnyVector{AnyDict{{"_id", INT64_C(4)}, {"value", INT64_C(2)}}};

        auto r1 = Realm::get_shared_realm(config1);
        auto r2 = Realm::get_shared_realm(config2);

        TestContext c1(r1);
        TestContext c2(r2);

        c1.defaults["pk after list"] = {
            {"int 1", INT64_C(10)},
            {"int 2", INT64_C(10)},
        };
        c2.defaults = c1.defaults;

        r1->begin_transaction();
        r2->begin_transaction();
        auto object1 = Object::create(c1, r1, *r1->schema().find("pk after list"), std::any(v1));
        auto object2 = Object::create(c2, r2, *r2->schema().find("pk after list"), std::any(v2));
        r2->commit_transaction();
        r1->commit_transaction();

        server.start();
        util::EventLoop::main().run_until([&] {
            return r1->read_group().get_table("class_array target")->size() == 4;
        });

        Obj obj = object1.get_obj();
        REQUIRE(obj.get<Int>("_id") == 7); // pk
        REQUIRE(obj.get_linklist("array 1").size() == 2);
        REQUIRE(obj.get<Int>("int 1") == 1); // non-default from r1
        REQUIRE(obj.get<Int>("int 2") == 2); // non-default from r2
        REQUIRE(obj.get_linklist("array 2").size() == 2);
    }
#endif
}

TEST_CASE("Multithreaded object notifications") {
    InMemoryTestFile config;
    auto r = Realm::get_shared_realm(config);
    r->update_schema({{"object", {{"value", PropertyType::Int}}}});

    r->begin_transaction();
    auto obj = r->read_group().get_table("class_object")->create_object();
    r->commit_transaction();

    Object object(r, obj);
    int64_t value = 0;
    auto token = object.add_notification_callback([&](auto) {
        value = obj.get<int64_t>("value");
    });
    constexpr const int end_value = 1000;

    // Try to verify that the notification machinery pins all versions that it
    // needs to pin by performing a large number of very small writes on a
    // background thread while the main thread is continously advancing via
    // each of the three ways to advance reads.
    JoiningThread thread([&] {
        // Not actually frozen, but we need to disable thread-checks for libuv platforms
        config.scheduler = util::Scheduler::make_frozen(VersionID());
        auto r = Realm::get_shared_realm(config);
        auto obj = *r->read_group().get_table("class_object")->begin();
        for (int i = 0; i <= end_value; ++i) {
            r->begin_transaction();
            obj.set<int64_t>("value", i);
            r->commit_transaction();
        }
    });

    SECTION("notify()") {
        REQUIRE_NOTHROW(util::EventLoop::main().run_until([&] {
            return value == end_value;
        }));
    }
    SECTION("refresh()") {
        while (value < end_value) {
            REQUIRE_NOTHROW(r->refresh());
        }
    }
    SECTION("begin_transaction()") {
        while (value < end_value) {
            REQUIRE_NOTHROW(r->begin_transaction());
            r->cancel_transaction();
        }
    }
}

TEST_CASE("Embedded Object") {
    Schema schema{
        {"all types",
         {
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"object", PropertyType::Object | PropertyType::Nullable, "link target"},
             {"array", PropertyType::Object | PropertyType::Array, "array target"},
         }},
        {"all types no pk",
         {
             {"value", PropertyType::Int},
             {"object", PropertyType::Object | PropertyType::Nullable, "link target"},
             {"array", PropertyType::Object | PropertyType::Array, "array target"},
         }},
        {"link target",
         ObjectSchema::ObjectType::Embedded,
         {
             {"value", PropertyType::Int},
         }},
        {"array target",
         ObjectSchema::ObjectType::Embedded,
         {
             {"value", PropertyType::Int},
         }},
    };
    InMemoryTestFile config;
    config.automatic_change_notifications = false;
    config.schema_mode = SchemaMode::Automatic;
    config.schema = schema;

    auto realm = Realm::get_shared_realm(config);
    CppContext ctx(realm);

    auto create = [&](std::any&& value, CreatePolicy policy = CreatePolicy::UpdateAll) {
        realm->begin_transaction();
        auto obj = Object::create(ctx, realm, *realm->schema().find("all types"), value, policy);
        realm->commit_transaction();
        return obj;
    };

    SECTION("Basic object creation") {
        auto obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"object", AnyDict{{"value", INT64_C(10)}}},
            {"array", AnyVector{AnyDict{{"value", INT64_C(20)}}, AnyDict{{"value", INT64_C(30)}}}},
        });

        REQUIRE(obj.get_obj().get<int64_t>("_id") == 1);
        auto linked_obj = util::any_cast<Object>(obj.get_property_value<std::any>(ctx, "object")).get_obj();
        REQUIRE(linked_obj.is_valid());
        REQUIRE(linked_obj.get<int64_t>("value") == 10);
        auto list = util::any_cast<List>(obj.get_property_value<std::any>(ctx, "array"));
        REQUIRE(list.size() == 2);
        REQUIRE(list.get(0).get<int64_t>("value") == 20);
        REQUIRE(list.get(1).get<int64_t>("value") == 30);
    }

    SECTION("set_property_value() on link to embedded object") {
        auto obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"object", AnyDict{{"value", INT64_C(10)}}},
            {"array", AnyVector{AnyDict{{"value", INT64_C(20)}}, AnyDict{{"value", INT64_C(30)}}}},
        });

        SECTION("throws when given a managed object") {
            realm->begin_transaction();
            REQUIRE_EXCEPTION(obj.set_property_value(ctx, "object", obj.get_property_value<std::any>(ctx, "object")),
                              InvalidArgument, "Cannot set a link to an existing managed embedded object");
            realm->cancel_transaction();
        }

        SECTION("replaces object when given a dictionary and CreatePolicy::UpdateAll") {
            realm->begin_transaction();
            auto old_linked = util::any_cast<Object>(obj.get_property_value<std::any>(ctx, "object"));
            obj.set_property_value(ctx, "object", std::any(AnyDict{{"value", INT64_C(40)}}));
            auto new_linked = util::any_cast<Object>(obj.get_property_value<std::any>(ctx, "object"));
            REQUIRE_FALSE(old_linked.is_valid());
            REQUIRE(new_linked.get_obj().get<int64_t>("value") == 40);
            realm->cancel_transaction();
        }

        SECTION("mutates existing object when given a dictionary and CreatePolicy::UpdateModified") {
            realm->begin_transaction();
            auto old_linked = util::any_cast<Object>(obj.get_property_value<std::any>(ctx, "object"));
            obj.set_property_value(ctx, "object", std::any(AnyDict{{"value", INT64_C(40)}}),
                                   CreatePolicy::UpdateModified);
            auto new_linked = util::any_cast<Object>(obj.get_property_value<std::any>(ctx, "object"));
            REQUIRE(old_linked.is_valid());
            REQUIRE(old_linked.get_obj() == new_linked.get_obj());
            REQUIRE(new_linked.get_obj().get<int64_t>("value") == 40);
            realm->cancel_transaction();
        }

        SECTION("can set embedded link to null") {
            realm->begin_transaction();
            auto old_linked = util::any_cast<Object>(obj.get_property_value<std::any>(ctx, "object"));
            obj.set_property_value(ctx, "object", std::any());
            auto new_linked = obj.get_property_value<std::any>(ctx, "object");
            REQUIRE_FALSE(old_linked.is_valid());
            REQUIRE_FALSE(new_linked.has_value());
            realm->cancel_transaction();
        }
    }

    SECTION("set_property_value() on list of embedded objects") {
        auto obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"array", AnyVector{AnyDict{{"value", INT64_C(1)}}, AnyDict{{"value", INT64_C(2)}}}},
        });
        List list(realm, obj.get_obj().get_linklist("array"));
        auto obj2 = create(AnyDict{
            {"_id", INT64_C(2)},
            {"array", AnyVector{AnyDict{{"value", INT64_C(1)}}, AnyDict{{"value", INT64_C(2)}}}},
        });
        List list2(realm, obj2.get_obj().get_linklist("array"));

        SECTION("throws when given a managed object") {
            realm->begin_transaction();
            REQUIRE_THROWS_WITH(obj.set_property_value(ctx, "array", std::any{AnyVector{list2.get(0)}}),
                                "Cannot add an existing managed embedded object to a List.");
            realm->cancel_transaction();
        }

        SECTION("replaces objects when given a dictionary and CreatePolicy::UpdateAll") {
            realm->begin_transaction();
            auto old_obj_1 = list.get(0);
            auto old_obj_2 = list.get(1);
            obj.set_property_value(ctx, "array",
                                   std::any(AnyVector{AnyDict{{"value", INT64_C(1)}}, AnyDict{{"value", INT64_C(2)}},
                                                      AnyDict{{"value", INT64_C(3)}}}),
                                   CreatePolicy::UpdateAll);
            REQUIRE(list.size() == 3);
            REQUIRE_FALSE(old_obj_1.is_valid());
            REQUIRE_FALSE(old_obj_2.is_valid());
            REQUIRE(list.get(0).get<int64_t>("value") == 1);
            REQUIRE(list.get(1).get<int64_t>("value") == 2);
            REQUIRE(list.get(2).get<int64_t>("value") == 3);
            realm->cancel_transaction();
        }

        SECTION("mutates existing objects when given a dictionary and CreatePolicy::UpdateModified") {
            realm->begin_transaction();
            auto old_obj_1 = list.get(0);
            auto old_obj_2 = list.get(1);
            obj.set_property_value(ctx, "array",
                                   std::any(AnyVector{AnyDict{{"value", INT64_C(1)}}, AnyDict{{"value", INT64_C(2)}},
                                                      AnyDict{{"value", INT64_C(3)}}}),
                                   CreatePolicy::UpdateModified);
            REQUIRE(list.size() == 3);
            REQUIRE(old_obj_1.is_valid());
            REQUIRE(old_obj_2.is_valid());
            REQUIRE(old_obj_1.get<int64_t>("value") == 1);
            REQUIRE(old_obj_2.get<int64_t>("value") == 2);
            REQUIRE(list.get(2).get<int64_t>("value") == 3);
            realm->cancel_transaction();
        }

        SECTION("clears list when given null") {
            realm->begin_transaction();
            obj.set_property_value(ctx, "array", std::any());
            REQUIRE(list.size() == 0);
            realm->cancel_transaction();
        }
    }

    SECTION("create with UpdateModified diffs child objects") {
        auto obj = create(AnyDict{
            {"_id", INT64_C(1)},
            {"object", AnyDict{{"value", INT64_C(10)}}},
            {"array", AnyVector{AnyDict{{"value", INT64_C(20)}}, AnyDict{{"value", INT64_C(30)}}}},
        });

        auto array_table = realm->read_group().get_table("class_array target");
        Results result(realm, array_table);

        bool obj_callback_called = false;
        auto token = obj.add_notification_callback([&](CollectionChangeSet) {
            obj_callback_called = true;
        });
        bool list_callback_called = false;
        auto token1 = result.add_notification_callback([&](CollectionChangeSet) {
            list_callback_called = true;
        });
        advance_and_notify(*realm);

        // Update with identical value
        create(
            AnyDict{
                {"_id", INT64_C(1)},
                {"object", AnyDict{{"value", INT64_C(10)}}},
            },
            CreatePolicy::UpdateModified);

        obj_callback_called = false;
        list_callback_called = false;
        advance_and_notify(*realm);
        REQUIRE(!obj_callback_called);
        REQUIRE(!list_callback_called);

        // Update with different values
        create(
            AnyDict{
                {"_id", INT64_C(1)},
                {"array", AnyVector{AnyDict{{"value", INT64_C(40)}}, AnyDict{{"value", INT64_C(50)}}}},
            },
            CreatePolicy::UpdateModified);

        obj_callback_called = false;
        list_callback_called = false;
        advance_and_notify(*realm);
        REQUIRE(!obj_callback_called);
        REQUIRE(list_callback_called);
    }

    SECTION("deleting parent object sends change notification") {
        auto parent = create(AnyDict{
            {"_id", INT64_C(1)},
            {"object", AnyDict{{"value", INT64_C(10)}}},
            {"array", AnyVector{AnyDict{{"value", INT64_C(20)}}, AnyDict{{"value", INT64_C(30)}}}},
        });

        CppContext ctx(realm);
        auto child = util::any_cast<Object>(parent.get_property_value<std::any>(ctx, "object"));

        int calls = 0;
        auto token = child.add_notification_callback([&](CollectionChangeSet const& c) {
            if (++calls == 2) {
                REQUIRE_INDICES(c.deletions, 0);
            }
        });
        advance_and_notify(*realm);
        REQUIRE(calls == 1);

        realm->begin_transaction();
        parent.get_obj().remove();
        realm->commit_transaction();
        advance_and_notify(*realm);
        REQUIRE(calls == 2);
    }
}

#if REALM_ENABLE_SYNC

TEST_CASE("Asymmetric Object") {
    Schema schema{
        {"asymmetric",
         ObjectSchema::ObjectType::TopLevelAsymmetric,
         {{"_id", PropertyType::Int, Property::IsPrimary{true}}}},
        {"asymmetric_link",
         ObjectSchema::ObjectType::TopLevelAsymmetric,
         {
             {"_id", PropertyType::Int, Property::IsPrimary{true}},
             {"location", PropertyType::Mixed | PropertyType::Nullable},
         }},
        {"table", {{"_id", PropertyType::Int, Property::IsPrimary{true}}}},
    };

    TestSyncManager tsm({}, {/*.start_immediately =*/false});
    SyncTestFile config(tsm.fake_user(), schema, SyncConfig::FLXSyncEnabled{});
    config.sync_config->flx_sync_requested = true;

    auto realm = Realm::get_shared_realm(config);
    {
        auto mut_subs = realm->get_latest_subscription_set().make_mutable_copy();
        mut_subs.insert_or_assign(Query(realm->read_group().get_table("class_table")));
        std::move(mut_subs).commit();
    }
    CppContext ctx(realm);

    auto create = [&](std::any&& value, std::string table_name, CreatePolicy policy = CreatePolicy::ForceCreate) {
        realm->begin_transaction();
        auto obj = Object::create(ctx, realm, *realm->schema().find(table_name), value, policy);
        realm->commit_transaction();
        return obj;
    };

    SECTION("Basic object creation") {
        auto obj = create(AnyDict{{"_id", INT64_C(1)}}, "asymmetric");
        // Object returned is not valid.
        REQUIRE(!obj.get_obj().is_valid());
        // Object gets deleted immediately.
        REQUIRE(realm->is_empty());
    }

    SECTION("Re-open realm") {
        realm->close();
        realm.reset();
        realm = Realm::get_shared_realm(config);
    }

    SECTION("Delete ephemeral object before comitting") {
        realm->begin_transaction();
        auto obj = realm->read_group().get_table("class_asymmetric")->create_object_with_primary_key(1);
        obj.remove();
        realm->commit_transaction();
        REQUIRE(!obj.is_valid());
        REQUIRE(realm->is_empty());
    }

    SECTION("Outgoing link not allowed") {
        auto obj = create(AnyDict{{"_id", INT64_C(1)}}, "table");
        auto table = realm->read_group().get_table("class_table");
        REQUIRE_EXCEPTION(create(
                              AnyDict{
                                  {"_id", INT64_C(1)},
                                  {"location", Mixed(ObjLink{table->get_key(), obj.get_obj().get_key()})},
                              },
                              "asymmetric_link"),
                          IllegalOperation, "Links not allowed in asymmetric tables");
    }
}

TEST_CASE("KeyPath generation - star notation") {
    Schema schema{
        {"Person",
         {
             {"name", PropertyType::String},
             {"age", PropertyType::Int},
             {"children", PropertyType::Object | PropertyType::Array, "Child"},
         }},
        {"Child",
         {
             {"name", PropertyType::String},
             {"favoritePet", PropertyType::Object | PropertyType::Nullable, "Pet"},
         },
         {
             {"parent", PropertyType::LinkingObjects | PropertyType::Array, "Person", "children"},
         }},
        {"Pet",
         ObjectSchema::ObjectType::Embedded,
         {
             {"name", PropertyType::String},
             {"breed", PropertyType::String},
         }},
    };
    InMemoryTestFile config;
    config.automatic_change_notifications = false;
    config.schema_mode = SchemaMode::Automatic;
    config.schema = schema;

    auto realm = Realm::get_shared_realm(config);

    auto kpa = realm->create_key_path_array("Person", {"*.*.*"});
    CHECK(kpa.size() == 8);
    // {class_Person:name}
    // {class_Person:age}
    // {class_Person:children}{class_Child:name}
    // {class_Person:children}{class_Child:favoritePet}{class_Pet:name}
    // {class_Person:children}{class_Child:favoritePet}{class_Pet:breed}
    // {class_Person:children}{class_Child:{class_Person:children}->}{class_Person:name}
    // {class_Person:children}{class_Child:{class_Person:children}->}{class_Person:age}
    // {class_Person:children}{class_Child:{class_Person:children}->}{class_Person:children}
    // realm->print_key_path_array(kpa);

    kpa = realm->create_key_path_array("Person", {"*.name"});
    CHECK(kpa.size() == 1);
    // {class_Person:children}{class_Child:name}
    // realm->print_key_path_array(kpa);

    kpa = realm->create_key_path_array("Person", {"*.*.breed"});
    CHECK(kpa.size() == 1);
    // {class_Person:children}{class_Child:favoritePet}{class_Pet:breed}
    // realm->print_key_path_array(kpa);

    kpa = realm->create_key_path_array("Child", {"*.name"});
    CHECK(kpa.size() == 2);
    // {class_Child:favoritePet}{class_Pet:name}
    // {class_Child:{class_Person:children}->}{class_Person:name}
    // realm->print_key_path_array(kpa);

    kpa = realm->create_key_path_array("Person", {"children.*.breed"});
    CHECK(kpa.size() == 1);
    // {class_Person:children}{class_Child:favoritePet}{class_Pet:breed}
    // realm->print_key_path_array(kpa);

    CHECK_THROWS_AS(realm->create_key_path_array("Person", {"children.favoritePet.colour"}), InvalidArgument);
    CHECK_THROWS_AS(realm->create_key_path_array("Person", {"*.myPet.breed"}), InvalidArgument);
}

#endif // REALM_ENABLE_SYNC
