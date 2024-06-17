/*************************************************************************
 *
 * Copyright 2024 Realm Inc.
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

#include "testsettings.hpp"

#include <cstring>
#include <string>
#include <sstream>

#include <realm.hpp>
#include <realm/string_data.hpp>
#include <realm/unicode.hpp>
#include <realm/string_interner.hpp>

#include "test.hpp"

using namespace realm;


TEST(StringInterner_Basic_Creation)
{
    Group group;
    TableRef table = group.add_table("test");
    auto string_col_key = table->add_column(type_String, "string");
    auto obj = table->create_object();
    std::string my_string = "aaaaaaaaaaaaaaa";
    obj.set(string_col_key, StringData(my_string));

    Array dummy_parent{obj.get_alloc()};
    dummy_parent.create(realm::NodeHeader::type_HasRefs);
    dummy_parent.add(0);

    StringInterner string_interner(obj.get_alloc(), dummy_parent, string_col_key, true);
    auto id = string_interner.intern(obj.get_any(string_col_key).get_string());

    const auto stored_id = string_interner.lookup(StringData(my_string));
    CHECK(stored_id);
    CHECK(*stored_id == id);

    CHECK(string_interner.compare(StringData(my_string), *stored_id) == 0); // should be equal
    const auto origin_string = string_interner.get(id);
    CHECK(obj.get_any(string_col_key).get_string() == origin_string);

    CHECK(string_interner.compare(*stored_id, id) == 0); // compare agaist self.
}

ONLY(StringInterner_Creation_Multiple_String_One_ColKey)
{
    Group group;
    TableRef table = group.add_table("test");
    const auto colkey = table->add_column(type_String, "string");
    auto obj = table->create_object();

    Allocator& alloc = obj.get_alloc();
    Array dummy_parent{alloc};
    dummy_parent.create(realm::NodeHeader::type_HasRefs);
    dummy_parent.add(0);
    StringID prev_string_id{0};

    // every leaf can contain max 15 entries, after thant it
    // a new leaf is added. So this loop should hit this limit

    for (size_t i = 0; i < 20; ++i) {
        std::string my_string = "aaaaaaaaaaaaaaa" + std::to_string(i);
        obj.set(colkey, StringData(my_string));


        auto string_interner = std::make_unique<StringInterner>(alloc, dummy_parent, colkey, true);

        const auto& db_string = obj.get_any(colkey).get_string();
        auto id = string_interner->intern(db_string);

        CHECK(prev_string_id == id - 1);
        // id 16, one full leaf with values, searching for the 16th string  is failing.
        const auto stored_id = string_interner->lookup(StringData(db_string));
        CHECK(stored_id);
        CHECK(*stored_id == id);

        CHECK(string_interner->compare(StringData(my_string), *stored_id) == 0); // should be equal
        const auto origin_string = string_interner->get(id);
        CHECK(obj.get_any(colkey).get_string() == origin_string);

        CHECK(string_interner->compare(*stored_id, id) == 0); // compare agaist self.
        prev_string_id = id;
    }
}

TEST(StringInterner_Creation_Multiple_String_ColKey)
{
    Group group;
    TableRef table = group.add_table("test");

    std::vector<std::string> string_col_names;
    std::vector<ColKey> col_keys;

    for (size_t i = 0; i < 10; ++i)
        string_col_names.push_back("string_" + std::to_string(i));

    for (const auto& col_name : string_col_names)
        col_keys.push_back(table->add_column(type_String, col_name));

    auto obj = table->create_object();

    std::vector<std::string> strings;
    std::string my_string = "aaaaaaaaaaaaaaa";
    for (size_t i = 0; i < col_keys.size(); ++i) {
        strings.push_back(my_string + std::to_string(i));
        obj.set(col_keys[i], StringData(strings[i]));
    }

    Allocator& alloc = obj.get_alloc();

    Array dummy_parent{alloc};
    dummy_parent.create(realm::NodeHeader::type_HasRefs);
    std::vector<std::unique_ptr<StringInterner>> interners;
    for (size_t i = 0; i < col_keys.size(); ++i) {
        dummy_parent.add(0);
        auto interner = std::make_unique<StringInterner>(alloc, dummy_parent, col_keys[i], true);
        interners.push_back(std::move(interner));
        interners.back()->update_from_parent(false);
    }

    for (size_t i = 0; i < interners.size(); ++i) {
        auto& string_interner = *interners[i];
        const auto& db_string = obj.get_any(col_keys[i]).get_string();
        auto id = string_interner.intern(db_string);
        const auto stored_id = string_interner.lookup(StringData(strings[i]));
        CHECK(stored_id);
        CHECK(*stored_id == id);

        CHECK(string_interner.compare(StringData(strings[i]), *stored_id) == 0); // should be equal
        const auto origin_string = string_interner.get(id);
        CHECK(obj.get_any(col_keys[i]).get_string() == origin_string);

        CHECK(string_interner.compare(*stored_id, id) == 0); // compare agaist self.
    }
}
