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

#ifndef REALM_STRING_INTERNER_HPP
#define REALM_STRING_INTERNER_HPP

#include <realm/array_unsigned.hpp>
#include <realm/utilities.hpp>
#include <realm/array.hpp>
#include <realm/keys.hpp>
#include <realm/alloc.hpp>

#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>

struct CompressedStringView;

namespace realm {

using StringID = size_t;

class StringCompressor;

struct CachedString {
    uint8_t m_weight = 0;
    std::unique_ptr<std::string> m_decompressed;
};

class StringInterner {
public:
    // To be used exclusively from Table
    StringInterner(Allocator& alloc, Array& parent, ColKey col_key, bool writable);
    void update_from_parent(bool writable);
    ~StringInterner();

    // To be used from Obj and for searching
    StringID intern(StringData);
    std::optional<StringID> lookup(StringData);
    int compare(StringID A, StringID B);
    int compare(StringData, StringID A);
    StringData get(StringID);

private:
    Array& m_parent; // need to be able to check if this is attached or not
    Array m_top;
    // Compressed strings are stored in blocks of 256.
    // One array holds refs to all blocks:
    Array m_data;
    // In-memory representation of a block. Either only the ref to it,
    // or a full vector of views into the block.
    struct DataLeaf;
    // in-memory metadata for faster access to compressed strings. Mirrors m_data.
    std::vector<DataLeaf> m_compressed_leafs;
    // 'm_hash_map' is used for mapping hash of uncompressed string to string id.
    Array m_hash_map;
    // the block of compressed strings we're currently appending to:
    ArrayUnsigned m_current_string_leaf;
    // an array of strings we're currently appending to. This is used instead
    // when ever we meet a string too large to be placed inline.
    Array m_current_long_string_node;
    void rebuild_internal();
    CompressedStringView& get_compressed(StringID id);
    // return true if the leaf was reloaded
    bool load_leaf_if_needed(DataLeaf& leaf);
    // return 'true' if the new ref was different and forced a reload
    bool load_leaf_if_new_ref(DataLeaf& leaf, ref_type new_ref);
    ColKey m_col_key; // for validation
    std::unique_ptr<StringCompressor> m_compressor;
    // At the moment we need to keep decompressed strings around if they've been
    // returned to the caller, since we're handing
    // out StringData references to their storage. This is a temporary solution.
    std::vector<CachedString> m_decompressed_strings;
    std::vector<StringID> m_in_memory_strings;
    // Mutual exclusion is needed for frozen transactions only. Live objects are
    // only used in single threaded contexts so don't need them. For now, just use always.
    std::mutex m_mutex;
};
} // namespace realm

#endif