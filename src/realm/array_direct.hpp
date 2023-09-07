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

#ifndef REALM_ARRAY_DIRECT_HPP
#define REALM_ARRAY_DIRECT_HPP

#include <cstring>
#include <realm/utilities.hpp>
#include <realm/alloc.hpp>

// clang-format off
/* wid == 16/32 likely when accessing offsets in B tree */
#define REALM_TEMPEX(fun, wid, arg) \
    if (wid == 16) {fun<16> arg;} \
    else if (wid == 32) {fun<32> arg;} \
    else if (wid == 0) {fun<0> arg;} \
    else if (wid == 1) {fun<1> arg;} \
    else if (wid == 2) {fun<2> arg;} \
    else if (wid == 4) {fun<4> arg;} \
    else if (wid == 8) {fun<8> arg;} \
    else if (wid == 64) {fun<64> arg;} \
    else {REALM_ASSERT_DEBUG(false); fun<0> arg;}

#define REALM_TEMPEX2(fun, targ, wid, arg) \
    if (wid == 16) {fun<targ, 16> arg;} \
    else if (wid == 32) {fun<targ, 32> arg;} \
    else if (wid == 0) {fun<targ, 0> arg;} \
    else if (wid == 1) {fun<targ, 1> arg;} \
    else if (wid == 2) {fun<targ, 2> arg;} \
    else if (wid == 4) {fun<targ, 4> arg;} \
    else if (wid == 8) {fun<targ, 8> arg;} \
    else if (wid == 64) {fun<targ, 64> arg;} \
    else {REALM_ASSERT_DEBUG(false); fun<targ, 0> arg;}

#define REALM_TEMPEX3(fun, targ1, wid, targ3, arg) \
    if (wid == 16) {fun<targ1, 16, targ3> arg;} \
    else if (wid == 32) {fun<targ1, 32, targ3> arg;} \
    else if (wid == 0) {fun<targ1, 0, targ3> arg;} \
    else if (wid == 1) {fun<targ1, 1, targ3> arg;} \
    else if (wid == 2) {fun<targ1, 2, targ3> arg;} \
    else if (wid == 4) {fun<targ1, 4, targ3> arg;} \
    else if (wid == 8) {fun<targ1, 8, targ3> arg;} \
    else if (wid == 64) {fun<targ1, 64, targ3> arg;} \
    else {REALM_ASSERT_DEBUG(false); fun<targ1, 0, targ3> arg;}

#define REALM_TEMPEX4(fun, targ1, targ3, targ4, wid, arg) \
    if (wid == 16) {fun<targ1, targ3, targ4, 16> arg;} \
    else if (wid == 32) {fun<targ1, targ3, targ4, 32> arg;} \
    else if (wid == 0) {fun<targ1, targ3, targ4, 0> arg;} \
    else if (wid == 1) {fun<targ1, targ3, targ4, 1> arg;} \
    else if (wid == 2) {fun<targ1, targ3, targ4, 2> arg;} \
    else if (wid == 4) {fun<targ1, targ3, targ4, 4> arg;} \
    else if (wid == 8) {fun<targ1, targ3, targ4, 8> arg;} \
    else if (wid == 64) {fun<targ1, targ3, targ4, 64> arg;} \
    else {REALM_ASSERT_DEBUG(false); fun<targ1, targ3, targ4, 0> arg;}
// clang-format on

namespace realm {

/// Takes a 64-bit value and returns the minimum number of bits needed
/// to fit the value. For alignment this is rounded up to nearest
/// log2. Posssible results {0, 1, 2, 4, 8, 16, 32, 64}
size_t bit_width(int64_t value);

// Direct access methods

template <size_t width>
void set_direct(char* data, size_t ndx, int_fast64_t value) noexcept
{
    if (width == 0) {
        REALM_ASSERT_DEBUG(value == 0);
        return;
    }
    else if (width == 1) {
        REALM_ASSERT_DEBUG(0 <= value && value <= 0x01);
        size_t byte_ndx = ndx / 8;
        size_t bit_ndx = ndx % 8;
        typedef unsigned char uchar;
        uchar* p = reinterpret_cast<uchar*>(data) + byte_ndx;
        *p = uchar((*p & ~(0x01 << bit_ndx)) | (int(value) & 0x01) << bit_ndx);
    }
    else if (width == 2) {
        REALM_ASSERT_DEBUG(0 <= value && value <= 0x03);
        size_t byte_ndx = ndx / 4;
        size_t bit_ndx = ndx % 4 * 2;
        typedef unsigned char uchar;
        uchar* p = reinterpret_cast<uchar*>(data) + byte_ndx;
        *p = uchar((*p & ~(0x03 << bit_ndx)) | (int(value) & 0x03) << bit_ndx);
    }
    else if (width == 4) {
        REALM_ASSERT_DEBUG(0 <= value && value <= 0x0F);
        size_t byte_ndx = ndx / 2;
        size_t bit_ndx = ndx % 2 * 4;
        typedef unsigned char uchar;
        uchar* p = reinterpret_cast<uchar*>(data) + byte_ndx;
        *p = uchar((*p & ~(0x0F << bit_ndx)) | (int(value) & 0x0F) << bit_ndx);
    }
    else if (width == 8) {
        REALM_ASSERT_DEBUG(std::numeric_limits<int8_t>::min() <= value &&
                           value <= std::numeric_limits<int8_t>::max());
        *(reinterpret_cast<int8_t*>(data) + ndx) = int8_t(value);
    }
    else if (width == 16) {
        REALM_ASSERT_DEBUG(std::numeric_limits<int16_t>::min() <= value &&
                           value <= std::numeric_limits<int16_t>::max());
        *(reinterpret_cast<int16_t*>(data) + ndx) = int16_t(value);
    }
    else if (width == 32) {
        REALM_ASSERT_DEBUG(std::numeric_limits<int32_t>::min() <= value &&
                           value <= std::numeric_limits<int32_t>::max());
        *(reinterpret_cast<int32_t*>(data) + ndx) = int32_t(value);
    }
    else if (width == 64) {
        REALM_ASSERT_DEBUG(std::numeric_limits<int64_t>::min() <= value &&
                           value <= std::numeric_limits<int64_t>::max());
        *(reinterpret_cast<int64_t*>(data) + ndx) = int64_t(value);
    }
    else {
        REALM_ASSERT_DEBUG(false);
    }
}

inline void set_direct(char* data, size_t width, size_t ndx, int_fast64_t value) noexcept
{
    REALM_TEMPEX(set_direct, width, (data, ndx, value));
}

template <size_t width>
void fill_direct(char* data, size_t begin, size_t end, int_fast64_t value) noexcept
{
    for (size_t i = begin; i != end; ++i)
        set_direct<width>(data, i, value);
}

template <int w>
int64_t get_direct(const char* data, size_t ndx) noexcept
{
    if (w == 0) {
        return 0;
    }
    if (w == 1) {
        size_t offset = ndx >> 3;
        return (data[offset] >> (ndx & 7)) & 0x01;
    }
    if (w == 2) {
        size_t offset = ndx >> 2;
        return (data[offset] >> ((ndx & 3) << 1)) & 0x03;
    }
    if (w == 4) {
        size_t offset = ndx >> 1;
        return (data[offset] >> ((ndx & 1) << 2)) & 0x0F;
    }
    if (w == 8) {
        return *reinterpret_cast<const signed char*>(data + ndx);
    }
    if (w == 16) {
        size_t offset = ndx * 2;
        return *reinterpret_cast<const int16_t*>(data + offset);
    }
    if (w == 32) {
        size_t offset = ndx * 4;
        return *reinterpret_cast<const int32_t*>(data + offset);
    }
    if (w == 64) {
        size_t offset = ndx * 8;
        return *reinterpret_cast<const int64_t*>(data + offset);
    }
    REALM_ASSERT_DEBUG(false);
    return int64_t(-1);
}

inline int64_t get_direct(const char* data, size_t width, size_t ndx) noexcept
{
    REALM_TEMPEX(return get_direct, width, (data, ndx));
}

// Read a bit field of up to 64 bits.
// - Any alignment and size is supported
// - The start of the 'data' area must be 64 bit aligned in all cases.
// - For fields of 64-bit or less, the first 64-bit word is filled with the zero-extended
//   value of the bitfield.
inline uint64_t read_bitfield(const char* data_area, size_t field_position, size_t width)
{
    // ectract data based on 64-bit word memory access and some bit fiddling
    size_t offset_begin = field_position;
    size_t offset_end = offset_begin + width - 1;
    size_t offset_begin_word = offset_begin >> 6;
    size_t offset_end_word = offset_end >> 6;
    uint64_t begin_word = ((const uint64_t*)data_area)[offset_begin_word];
    begin_word >>= (offset_begin - offset_begin_word);
    // take into account possible crossing of alignment boundary
    if (offset_begin_word != offset_end_word) {
        auto bits_in_end_word = offset_end - (offset_end_word << 6);
        auto bits_in_begin_word = width - bits_in_end_word;
        begin_word &= ~((1ULL << bits_in_begin_word) - 1);
        uint64_t end_word = ((const uint64_t*)data_area)[offset_end_word];
        end_word <<= bits_in_begin_word;
        begin_word |= end_word;
    }
    // mask out anything above the bits we need:
    // technically this is undef for width=64 bit, but should in practice
    // give the correct result.
    begin_word &= (1ULL << width) - 1;
    return begin_word;
}

inline void write_bitfield(char* data_area, size_t field_position, size_t width, uint64_t value)
{
    // entries 64 bit or less:
    // ectract data based on 64-bit word memory access and some bit fiddling
    size_t offset_begin = field_position;
    size_t offset_end = offset_begin + width - 1;
    size_t offset_begin_word = offset_begin >> 6;
    size_t offset_end_word = offset_end >> 6;
    // ensure all zeroes outside the bits we're interested in:
    value &= ((1ULL << width) - 1);
    // place low part (or all of) value in proper position within target word
    auto rot_first_word = offset_begin - (offset_begin_word << 6);
    auto mask = (size_t(-1) & ((1ULL << width) - 1)) << rot_first_word;
    uint64_t begin_word = ((const uint64_t*)data_area)[offset_begin_word];
    begin_word &= ~mask;
    begin_word |= value << rot_first_word;
    ((uint64_t*)data_area)[offset_begin_word] = begin_word;
    // take into account possible crossing of alignment boundary
    if (offset_begin_word != offset_end_word) {
        auto bits_in_end_word = offset_end - (offset_end_word << 6);
        auto bits_in_begin_word = width - bits_in_end_word;
        value >>= bits_in_begin_word;
        mask = (size_t(-1)) & ((1ULL << bits_in_end_word) - 1);
        uint64_t end_word = ((const uint64_t*)data_area)[offset_end_word];
        end_word &= ~mask;
        end_word |= value;
        ((uint64_t*)data_area)[offset_end_word] = end_word;
    }
}

// iterator useful for scanning arrays faster than by indexing each element
// supports arrays of pairs by differentiating field size and step size.
class bf_ref;
class bf_iterator {
    uint64_t* data_area;
    uint64_t* first_word_ptr;
    int field_position;
    uint8_t field_size;
    uint8_t step_size; // may be different than field_size if used for arrays of pairs

public:
    bf_iterator(uint64_t* data_area, int initial_offset, int field_size, int step_size, int index)
        : data_area(data_area)
        , field_size(field_size)
        , step_size(step_size)
    {
        field_position = initial_offset + index * step_size;
        first_word_ptr = data_area + (field_position >> 6);
    }
    uint64_t get_value() const
    {
        auto in_word_position = field_position & 0x3F;
        auto first_word = first_word_ptr[0];
        uint64_t result = first_word >> in_word_position;
        // note: above shifts in zeroes above the bitfield
        if (in_word_position + field_size > 64) {
            auto first_word_size = 64 - in_word_position;
            auto second_word = first_word_ptr[1];
            result |= second_word << first_word_size;
            // note: above shifts in zeroes below the bits we want
        }
        // discard any bits above the field we want
        result &= (1ULL << field_size) - 1;
        return result;
    }
    void set_value(uint64_t value) const
    {
        static_cast<void>(value);
    }
    void operator++()
    {
        auto next_field_position = field_position + step_size;
        if ((next_field_position >> 6) > (field_position >> 6)) {
            first_word_ptr = data_area + (next_field_position >> 6);
        }
        field_position = next_field_position;
    }
    uint64_t operator*() const
    {
        return get_value();
    }
    bf_ref operator*();
};

class bf_ref {
    bf_iterator it;

public:
    bf_ref(bf_iterator& it)
        : it(it)
    {
    }
    operator uint64_t() const
    {
        return it.get_value();
    }
    uint64_t operator=(uint64_t value)
    {
        it.set_value(value);
        return value;
    }
};

inline bf_ref bf_iterator::operator*()
{
    return bf_ref(*this);
}

inline int64_t sign_extend_field(size_t width, uint64_t value)
{
    uint64_t sign_mask = 1ULL << (width - 1);
    if (value & sign_mask) { // got a negative value
        uint64_t negative_extension = -sign_mask;
        value |= negative_extension;
        return int64_t(value);
    }
    else {
        // zero out anything above the sign bit
        // (actually, also zero out the sign bit, but it is already known to be zero)
        uint64_t below_sign_mask = sign_mask - 1;
        value &= below_sign_mask;
        return int64_t(value);
    }
}

template <int width>
inline std::pair<int64_t, int64_t> get_two(const char* data, size_t ndx) noexcept
{
    return std::make_pair(to_size_t(get_direct<width>(data, ndx + 0)), to_size_t(get_direct<width>(data, ndx + 1)));
}

inline std::pair<int64_t, int64_t> get_two(const char* data, size_t width, size_t ndx) noexcept
{
    REALM_TEMPEX(return get_two, width, (data, ndx));
}


// Lower/upper bound in sorted sequence
// ------------------------------------
//
//   3 3 3 4 4 4 5 6 7 9 9 9
//   ^     ^     ^     ^     ^
//   |     |     |     |     |
//   |     |     |     |      -- Lower and upper bound of 15
//   |     |     |     |
//   |     |     |      -- Lower and upper bound of 8
//   |     |     |
//   |     |      -- Upper bound of 4
//   |     |
//   |      -- Lower bound of 4
//   |
//    -- Lower and upper bound of 1
//
// These functions are semantically identical to std::lower_bound() and
// std::upper_bound().
//
// We currently use binary search. See for example
// http://www.tbray.org/ongoing/When/200x/2003/03/22/Binary.
template <int width>
inline size_t lower_bound(const char* data, size_t size, int64_t value) noexcept
{
    // The binary search used here is carefully optimized. Key trick is to use a single
    // loop controlling variable (size) instead of high/low pair, and to keep updates
    // to size done inside the loop independent of comparisons. Further key to speed
    // is to avoid branching inside the loop, using conditional moves instead. This
    // provides robust performance for random searches, though predictable searches
    // might be slightly faster if we used branches instead. The loop unrolling yields
    // a final 5-20% speedup depending on circumstances.

    size_t low = 0;

    while (size >= 8) {
        // The following code (at X, Y and Z) is 3 times manually unrolled instances of (A) below.
        // These code blocks must be kept in sync. Meassurements indicate 3 times unrolling to give
        // the best performance. See (A) for comments on the loop body.
        // (X)
        size_t half = size / 2;
        size_t other_half = size - half;
        size_t probe = low + half;
        size_t other_low = low + other_half;
        int64_t v = get_direct<width>(data, probe);
        size = half;
        low = (v < value) ? other_low : low;

        // (Y)
        half = size / 2;
        other_half = size - half;
        probe = low + half;
        other_low = low + other_half;
        v = get_direct<width>(data, probe);
        size = half;
        low = (v < value) ? other_low : low;

        // (Z)
        half = size / 2;
        other_half = size - half;
        probe = low + half;
        other_low = low + other_half;
        v = get_direct<width>(data, probe);
        size = half;
        low = (v < value) ? other_low : low;
    }
    while (size > 0) {
        // (A)
        // To understand the idea in this code, please note that
        // for performance, computation of size for the next iteration
        // MUST be INDEPENDENT of the conditional. This allows the
        // processor to unroll the loop as fast as possible, and it
        // minimizes the length of dependence chains leading up to branches.
        // Making the unfolding of the loop independent of the data being
        // searched, also minimizes the delays incurred by branch
        // mispredictions, because they can be determined earlier
        // and the speculation corrected earlier.

        // Counterintuitive:
        // To make size independent of data, we cannot always split the
        // range at the theoretical optimal point. When we determine that
        // the key is larger than the probe at some index K, and prepare
        // to search the upper part of the range, you would normally start
        // the search at the next index, K+1, to get the shortest range.
        // We can only do this when splitting a range with odd number of entries.
        // If there is an even number of entries we search from K instead of K+1.
        // This potentially leads to redundant comparisons, but in practice we
        // gain more performance by making the changes to size predictable.

        // if size is even, half and other_half are the same.
        // if size is odd, half is one less than other_half.
        size_t half = size / 2;
        size_t other_half = size - half;
        size_t probe = low + half;
        size_t other_low = low + other_half;
        int64_t v = get_direct<width>(data, probe);
        size = half;
        // for max performance, the line below should compile into a conditional
        // move instruction. Not all compilers do this. To maximize chance
        // of succes, no computation should be done in the branches of the
        // conditional.
        low = (v < value) ? other_low : low;
    };

    return low;
}

// See lower_bound()
template <int width>
inline size_t upper_bound(const char* data, size_t size, int64_t value) noexcept
{
    size_t low = 0;
    while (size >= 8) {
        size_t half = size / 2;
        size_t other_half = size - half;
        size_t probe = low + half;
        size_t other_low = low + other_half;
        int64_t v = get_direct<width>(data, probe);
        size = half;
        low = (value >= v) ? other_low : low;

        half = size / 2;
        other_half = size - half;
        probe = low + half;
        other_low = low + other_half;
        v = get_direct<width>(data, probe);
        size = half;
        low = (value >= v) ? other_low : low;

        half = size / 2;
        other_half = size - half;
        probe = low + half;
        other_low = low + other_half;
        v = get_direct<width>(data, probe);
        size = half;
        low = (value >= v) ? other_low : low;
    }

    while (size > 0) {
        size_t half = size / 2;
        size_t other_half = size - half;
        size_t probe = low + half;
        size_t other_low = low + other_half;
        int64_t v = get_direct<width>(data, probe);
        size = half;
        low = (value >= v) ? other_low : low;
    };

    return low;
}
} // namespace realm

#endif /* ARRAY_TPL_HPP_ */
