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

#include <realm/array_timestamp.hpp>
#include <realm/array_integer_tpl.hpp>
#include <realm/impl/array_writer.hpp>

using namespace realm;

ArrayTimestamp::ArrayTimestamp(Allocator& a)
    : Array(a)
    , m_seconds(a)
    , m_nanoseconds(a)
{
    m_seconds.set_parent(this, 0);
    m_nanoseconds.set_parent(this, 1);
}

void ArrayTimestamp::create()
{
    Array::create(Array::type_HasRefs, false /* context_flag */, 2);

    MemRef seconds = ArrayIntNull::create_array(Array::type_Normal, false, 0, m_alloc);
    Array::set_as_ref(0, seconds.get_ref());
    MemRef nanoseconds = ArrayInteger::create_empty_array(Array::type_Normal, false, m_alloc);
    Array::set_as_ref(1, nanoseconds.get_ref());

    m_seconds.init_from_parent();
    m_nanoseconds.init_from_parent();
}

void ArrayTimestamp::init_from_mem(MemRef mem) noexcept
{
    Array::init_from_mem(mem);
    m_seconds.init_from_parent();
    m_nanoseconds.init_from_parent();
}

void ArrayTimestamp::set(size_t ndx, Timestamp value)
{
    if (value.is_null()) {
        return set_null(ndx);
    }

    util::Optional<int64_t> seconds = util::make_optional(value.get_seconds());
    int32_t nanoseconds = value.get_nanoseconds();

    m_seconds.set(ndx, seconds);
    m_nanoseconds.set(ndx, nanoseconds); // Throws
}

void ArrayTimestamp::insert(size_t ndx, Timestamp value)
{
    if (value.is_null()) {
        m_seconds.insert(ndx, util::none);
        m_nanoseconds.insert(ndx, 0); // Throws
    }
    else {
        util::Optional<int64_t> seconds = util::make_optional(value.get_seconds());
        int32_t nanoseconds = value.get_nanoseconds();

        m_seconds.insert(ndx, seconds);
        m_nanoseconds.insert(ndx, nanoseconds); // Throws
    }
}

namespace realm {

template <>
size_t ArrayTimestamp::find_first<Greater>(Timestamp value, size_t begin, size_t end) const noexcept
{
    if (value.is_null()) {
        return not_found;
    }
    int64_t sec = value.get_seconds();
    while (begin < end) {
        size_t ret = m_seconds.find_first<GreaterEqual>(sec, begin, end);

        if (ret == not_found)
            return not_found;

        util::Optional<int64_t> seconds = m_seconds.get(ret);
        if (*seconds > sec) {
            return ret;
        }
        // We now know that neither m_value nor current value is null and that seconds part equals
        // We are just missing to compare nanoseconds part
        int32_t nanos = int32_t(m_nanoseconds.get(ret));
        if (nanos > value.get_nanoseconds()) {
            return ret;
        }
        begin = ret + 1;
    }

    return not_found;
}

template <>
size_t ArrayTimestamp::find_first<Less>(Timestamp value, size_t begin, size_t end) const noexcept
{
    if (value.is_null()) {
        return not_found;
    }
    int64_t sec = value.get_seconds();
    while (begin < end) {
        size_t ret = m_seconds.find_first<LessEqual>(sec, begin, end);

        if (ret == not_found)
            return not_found;

        util::Optional<int64_t> seconds = m_seconds.get(ret);
        if (*seconds < sec) {
            return ret;
        }
        // We now know that neither m_value nor current value is null and that seconds part equals
        // We are just missing to compare nanoseconds part
        int32_t nanos = int32_t(m_nanoseconds.get(ret));
        if (nanos < value.get_nanoseconds()) {
            return ret;
        }
        begin = ret + 1;
    }

    return not_found;
}

template <>
size_t ArrayTimestamp::find_first<GreaterEqual>(Timestamp value, size_t begin, size_t end) const noexcept
{
    if (value.is_null()) {
        return m_seconds.find_first<Equal>(util::none, begin, end);
    }
    int64_t sec = value.get_seconds();
    while (begin < end) {
        size_t ret = m_seconds.find_first<GreaterEqual>(sec, begin, end);

        if (ret == not_found)
            return not_found;

        util::Optional<int64_t> seconds = m_seconds.get(ret);
        if (*seconds > sec) {
            return ret;
        }
        // We now know that neither m_value nor current value is null and that seconds part equals
        // We are just missing to compare nanoseconds part
        int32_t nanos = int32_t(m_nanoseconds.get(ret));
        if (nanos >= value.get_nanoseconds()) {
            return ret;
        }
        begin = ret + 1;
    }

    return not_found;
}

template <>
size_t ArrayTimestamp::find_first<LessEqual>(Timestamp value, size_t begin, size_t end) const noexcept
{
    if (value.is_null()) {
        return m_seconds.find_first<Equal>(util::none, begin, end);
    }
    int64_t sec = value.get_seconds();
    while (begin < end) {
        size_t ret = m_seconds.find_first<LessEqual>(sec, begin, end);

        if (ret == not_found)
            return not_found;

        util::Optional<int64_t> seconds = m_seconds.get(ret);
        if (*seconds < sec) {
            return ret;
        }
        // We now know that neither m_value nor current value is null and that seconds part equals
        // We are just missing to compare nanoseconds part
        int32_t nanos = int32_t(m_nanoseconds.get(ret));
        if (nanos <= value.get_nanoseconds()) {
            return ret;
        }
        begin = ret + 1;
    }

    return not_found;
}

template <>
size_t ArrayTimestamp::find_first<Equal>(Timestamp value, size_t begin, size_t end) const noexcept
{
    if (value.is_null()) {
        return m_seconds.find_first<Equal>(util::none, begin, end);
    }
    while (begin < end) {
        auto res = m_seconds.find_first(value.get_seconds(), begin, end);
        if (res == npos)
            return not_found;
        if (m_nanoseconds.get(res) == value.get_nanoseconds())
            return res;
        begin = res + 1;
    }
    return not_found;
}

template <>
size_t ArrayTimestamp::find_first<NotEqual>(Timestamp value, size_t begin, size_t end) const noexcept
{
    if (value.is_null()) {
        return m_seconds.find_first<NotEqual>(util::none, begin, end);
    }
    int64_t sec = value.get_seconds();
    while (begin < end) {
        util::Optional<int64_t> seconds = m_seconds.get(begin);
        if (!seconds || *seconds != sec) {
            return begin;
       }
       // We now know that neither m_value nor current value is null and that seconds part equals
       // We are just missing to compare nanoseconds part
       int32_t nanos = int32_t(m_nanoseconds.get(begin));
       if (nanos != value.get_nanoseconds()) {
           return begin;
       }
       ++begin;
    }
    return not_found;
}

void ArrayTimestamp::verify() const
{
#ifdef REALM_DEBUG
    m_seconds.verify();
    m_nanoseconds.verify();
    REALM_ASSERT(m_seconds.size() == m_nanoseconds.size());
#endif
}

ref_type ArrayTimestamp::typed_write(ref_type ref, _impl::ArrayWriterBase& out, Allocator& alloc)
{
    // timestamps could be compressed, but the formats we support at the moment are not producing
    // noticeable gains.
    Array top(alloc);
    top.init_from_ref(ref);
    REALM_ASSERT_DEBUG(top.size() == 2);

    TempArray written_top(2);

    auto rot0 = top.get_as_ref_or_tagged(0);
    auto rot1 = top.get_as_ref_or_tagged(1);
    REALM_ASSERT_DEBUG(rot0.is_ref() && rot0.get_as_ref());
    REALM_ASSERT_DEBUG(rot1.is_ref() && rot1.get_as_ref());
    written_top.set_as_ref(0, Array::write(rot0.get_as_ref(), alloc, out, out.only_modified, false));
    written_top.set_as_ref(1, Array::write(rot1.get_as_ref(), alloc, out, out.only_modified, false));

    return written_top.write(out);
}

} // namespace realm
