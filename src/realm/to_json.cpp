/*************************************************************************
 *
 * Copyright 2016 Realm Inc.
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
#include <realm/dictionary.hpp>
#include <realm/list.hpp>
#include <realm/set.hpp>
#include <external/json/json.hpp>
#include "realm/util/base64.hpp"

namespace realm {

void Group::schema_to_json(std::ostream& out, std::map<std::string, std::string>* opt_renames) const
{
    check_attached();

    std::map<std::string, std::string> renames;
    if (opt_renames) {
        renames = *opt_renames;
    }

    out << "[" << std::endl;

    auto keys = get_table_keys();
    int sz = int(keys.size());
    for (int i = 0; i < sz; ++i) {
        auto key = keys[i];
        ConstTableRef table = get_table(key);

        table->schema_to_json(out, renames);
        if (i < sz - 1)
            out << ",";
        out << std::endl;
    }

    out << "]" << std::endl;
}

void Group::to_json(std::ostream& out, size_t link_depth, std::map<std::string, std::string>* opt_renames,
                    JSONOutputMode output_mode) const
{
    check_attached();

    std::map<std::string, std::string> renames;
    if (opt_renames) {
        renames = *opt_renames;
    }

    out << "{" << std::endl;

    auto keys = get_table_keys();
    bool first = true;
    for (size_t i = 0; i < keys.size(); ++i) {
        auto key = keys[i];
        StringData name = get_table_name(key);
        if (renames.count(name))
            name = renames[name];

        ConstTableRef table = get_table(key);

        if (!table->is_embedded()) {
            if (!first)
                out << ",";
            out << "\"" << name << "\"";
            out << ":";
            table->to_json(out, link_depth, renames, output_mode);
            out << std::endl;
            first = false;
        }
    }

    out << "}" << std::endl;
}

void Table::to_json(std::ostream& out, size_t link_depth, const std::map<std::string, std::string>& renames,
                    JSONOutputMode output_mode) const
{
    // Represent table as list of objects
    out << "[";
    bool first = true;

    for (auto& obj : *this) {
        if (first) {
            first = false;
        }
        else {
            out << ",";
        }
        obj.to_json(out, link_depth, renames, output_mode);
    }

    out << "]";
}

void Obj::to_json(std::ostream& out, size_t link_depth, const std::map<std::string, std::string>& renames,
                  std::vector<ObjLink>& followed, JSONOutputMode output_mode) const
{
    followed.push_back(get_link());
    size_t new_depth = link_depth == not_found ? not_found : link_depth - 1;
    StringData name = "_key";
    bool prefixComma = false;
    if (renames.count(name))
        name = renames.at(name);
    out << "{";
    if (output_mode == output_mode_json) {
        prefixComma = true;
        out << "\"" << name << "\":" << this->m_key.value;
    }

    auto col_keys = m_table->get_column_keys();
    for (auto ck : col_keys) {
        name = m_table->get_column_name(ck);
        auto type = ck.get_type();
        if (renames.count(name))
            name = renames.at(name);

        if (prefixComma)
            out << ",";
        out << "\"" << name << "\":";
        prefixComma = true;

        TableRef target_table;
        ColKey pk_col_key;
        if (type == col_type_Link) {
            target_table = get_target_table(ck);
            pk_col_key = target_table->get_primary_key_column();
        }

        auto print_link = [&](const Mixed& val) {
            REALM_ASSERT(val.is_type(type_Link, type_TypedLink));
            TableRef tt = target_table;
            auto obj_key = val.get<ObjKey>();
            std::string table_info;
            std::string table_info_close;
            if (!tt) {
                // It must be a typed link
                tt = m_table->get_parent_group()->get_table(val.get_link().get_table_key());
                pk_col_key = tt->get_primary_key_column();
                if (output_mode == output_mode_xjson_plus) {
                    table_info = std::string("{ \"$link\": ");
                    table_info_close = " }";
                }

                table_info += std::string("{ \"table\": \"") + std::string(tt->get_name()) + "\", \"key\": ";
                table_info_close += " }";
            }
            if (pk_col_key && output_mode != output_mode_json) {
                out << table_info;
                tt->get_primary_key(obj_key).to_json(out, output_mode_xjson);
                out << table_info_close;
            }
            else {
                ObjLink link(tt->get_key(), obj_key);
                if (obj_key.is_unresolved()) {
                    out << "null";
                    return;
                }
                if (!tt->is_embedded()) {
                    if (link_depth == 0) {
                        out << table_info << obj_key.value << table_info_close;
                        return;
                    }
                    if ((link_depth == realm::npos &&
                         std::find(followed.begin(), followed.end(), link) != followed.end())) {
                        // We have detected a cycle in links
                        out << "{ \"table\": \"" << tt->get_name() << "\", \"key\": " << obj_key.value << " }";
                        return;
                    }
                }

                tt->get_object(obj_key).to_json(out, new_depth, renames, followed, output_mode);
            }
        };

        if (ck.is_collection()) {
            auto collection = get_collection_ptr(ck);
            collection->to_json(out, link_depth, output_mode, print_link);
        }
        else {
            auto val = get_any(ck);
            if (!val.is_null()) {
                if (type == col_type_Link) {
                    std::string close_string;
                    bool is_embedded = target_table->is_embedded();
                    bool link_depth_reached = !is_embedded && (link_depth == 0);

                    if (output_mode == output_mode_xjson_plus) {
                        out << "{ " << (is_embedded ? "\"$embedded" : "\"$link") << "\": ";
                        close_string += "}";
                    }
                    if ((link_depth_reached && output_mode == output_mode_json) ||
                        output_mode == output_mode_xjson_plus) {
                        out << "{ \"table\": \"" << target_table->get_name() << "\", "
                            << (is_embedded ? "\"value" : "\"key") << "\": ";
                        close_string += "}";
                    }

                    print_link(val);
                    out << close_string;
                }
                else if (val.is_type(type_TypedLink)) {
                    print_link(val);
                }
                else if (val.is_type(type_Dictionary)) {
                    DummyParent parent(m_table, val.get_ref());
                    Dictionary dict(parent, 0);
                    dict.to_json(out, link_depth, output_mode, print_link);
                }
                else if (val.is_type(type_List)) {
                    DummyParent parent(m_table, val.get_ref());
                    Lst<Mixed> list(parent, 0);
                    list.to_json(out, link_depth, output_mode, print_link);
                }
                else {
                    val.to_json(out, output_mode);
                }
            }
            else {
                out << "null";
            }
        }
    }
    out << "}";
    followed.pop_back();
}

namespace {
const char to_be_escaped[] = "\"\n\r\t\f\\\b";
const char encoding[] = "\"nrtf\\b";

template <class T>
inline void out_floats(std::ostream& out, T value)
{
    std::streamsize old = out.precision();
    out.precision(std::numeric_limits<T>::digits10 + 1);
    out << std::scientific << value;
    out.precision(old);
}

void out_string(std::ostream& out, std::string str)
{
    size_t p = str.find_first_of(to_be_escaped);
    while (p != std::string::npos) {
        char c = str[p];
        auto found = strchr(to_be_escaped, c);
        REALM_ASSERT(found);
        out << str.substr(0, p) << '\\' << encoding[found - to_be_escaped];
        str = str.substr(p + 1);
        p = str.find_first_of(to_be_escaped);
    }
    out << str;
}

void out_binary(std::ostream& out, BinaryData bin)
{
    const char* start = bin.data();
    const size_t len = bin.size();
    std::string encode_buffer;
    encode_buffer.resize(util::base64_encoded_size(len));
    util::base64_encode(start, len, encode_buffer.data(), encode_buffer.size());
    out << encode_buffer;
}
} // anonymous namespace


void Mixed::to_xjson(std::ostream& out) const noexcept
{
    switch (get_type()) {
        case type_Int:
            out << "{\"$numberLong\": \"";
            out << int_val;
            out << "\"}";
            break;
        case type_Bool:
            out << (bool_val ? "true" : "false");
            break;
        case type_Float:
            out << "{\"$numberDouble\": \"";
            out_floats<float>(out, float_val);
            out << "\"}";
            break;
        case type_Double:
            out << "{\"$numberDouble\": \"";
            out_floats<double>(out, double_val);
            out << "\"}";
            break;
        case type_String: {
            out << "\"";
            out_string(out, string_val);
            out << "\"";
            break;
        }
        case type_Binary: {
            out << "{\"$binary\": {\"base64\": \"";
            out_binary(out, binary_val);
            out << "\", \"subType\": \"00\"}}";
            break;
        }
        case type_Timestamp: {
            out << "{\"$date\": {\"$numberLong\": \"";
            int64_t timeMillis = date_val.get_seconds() * 1000 + date_val.get_nanoseconds() / 1000000;
            out << timeMillis;
            out << "\"}}";
            break;
        }
        case type_Decimal:
            out << "{\"$numberDecimal\": \"";
            out << decimal_val;
            out << "\"}";
            break;
        case type_ObjectId:
            out << "{\"$oid\": \"";
            out << id_val;
            out << "\"}";
            break;
        case type_UUID:
            out << "{\"$binary\": {\"base64\": \"";
            out << uuid_val.to_base64();
            out << "\", \"subType\": \"04\"}}";
            break;

        case type_TypedLink: {
            Mixed val(get<ObjLink>().get_obj_key());
            val.to_xjson(out);
            break;
        }
        case type_Link:
        case type_Mixed:
            break;
    }
}

void Mixed::to_xjson_plus(std::ostream& out) const noexcept
{

    // Special case for outputing a typedLink, otherwise just us out_mixed_xjson
    if (is_type(type_TypedLink)) {
        auto link = get<ObjLink>();
        out << "{ \"$link\": { \"table\": \"" << link.get_table_key() << "\", \"key\": ";
        Mixed val(link.get_obj_key());
        val.to_xjson(out);
        out << "}}";
        return;
    }

    to_xjson(out);
}

void Mixed::to_json(std::ostream& out, JSONOutputMode output_mode) const noexcept
{
    if (is_null()) {
        out << "null";
        return;
    }
    switch (output_mode) {
        case output_mode_xjson: {
            to_xjson(out);
            return;
        }
        case output_mode_xjson_plus: {
            to_xjson_plus(out);
            return;
        }
        case output_mode_json: {
            switch (get_type()) {
                case type_Int:
                    out << int_val;
                    break;
                case type_Bool:
                    out << (bool_val ? "true" : "false");
                    break;
                case type_Float:
                    out_floats<float>(out, float_val);
                    break;
                case type_Double:
                    out_floats<double>(out, double_val);
                    break;
                case type_String: {
                    out << "\"";
                    out_string(out, string_val);
                    out << "\"";
                    break;
                }
                case type_Binary: {
                    out << "\"";
                    out_binary(out, binary_val);
                    out << "\"";
                    break;
                }
                case type_Timestamp:
                    out << "\"";
                    out << date_val;
                    out << "\"";
                    break;
                case type_Decimal:
                    out << "\"";
                    out << decimal_val;
                    out << "\"";
                    break;
                case type_ObjectId:
                    out << "\"";
                    out << id_val;
                    out << "\"";
                    break;
                case type_UUID:
                    out << "\"";
                    out << uuid_val;
                    out << "\"";
                    break;
                case type_TypedLink:
                    out << "\"";
                    out << link_val;
                    out << "\"";
                    break;
                case type_Link:
                case type_Mixed:
                    break;
            }
        }
    }
}

} // namespace realm
