///////////////////////////////////////////////////////////////////////////
//
// Copyright 2022 Realm Inc.
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

#ifndef REALM_UTIL_FLAT_MAP_HPP
#define REALM_UTIL_FLAT_MAP_HPP

#include <vector>
#include <utility>   // std::pair
#include <algorithm> // std::lower_bound etc.
#include <type_traits>

#include <realm/util/backtrace.hpp>

namespace realm {
namespace util {

template <class K, class V, class Cmp = std::less<>, class Container = std::vector<std::pair<K, V>>>
struct FlatMap {
    using value_type = std::pair<K, V>;
    using key_type = K;
    using mapped_type = V;
    using container_type = Container;
    using iterator = typename Container::iterator;
    using const_iterator = typename Container::const_iterator;

    FlatMap() = default;
    FlatMap(const FlatMap&) = default;
    FlatMap(FlatMap&&) = default;
    FlatMap(Container&& values)
    {
        for (auto v : values) {
            insert(v);
        }
    }

    template <typename Iterator>
    FlatMap(Iterator begin, Iterator end)
    {
        for (; begin != end; ++begin) {
            insert(*begin);
        }
    }

    FlatMap(std::initializer_list<value_type> values)
        : FlatMap(values.begin(), values.end())
    {
    }

    FlatMap& operator=(const FlatMap&) = default;
    FlatMap& operator=(FlatMap&&) = default;

    V& at(K key)
    {
        auto it = lower_bound(key);
        if (it == end() || !keys_equal(it->first, key))
            it = m_data.emplace(it, std::move(key), V{}); // Throws
        return it->second;
    }

    const V& at(const K& key) const
    {
        auto it = find(key);
        if (it == end())
            throw util::out_of_range("no such key");
        return it->second;
    }

    V& operator[](const K& key)
    {
        return at(key); // Throws
    }

    iterator begin() noexcept
    {
        return m_data.begin();
    }
    iterator end() noexcept
    {
        return m_data.end();
    }
    const_iterator begin() const noexcept
    {
        return m_data.begin();
    }
    const_iterator end() const noexcept
    {
        return m_data.end();
    }

    bool empty() const noexcept
    {
        return m_data.empty();
    }

    size_t size() const noexcept
    {
        return m_data.size();
    }

    void clear() noexcept
    {
        m_data.clear();
    }

    std::pair<iterator, bool> insert(value_type value)
    {
        auto it = lower_bound(value.first);
        if (it != end() && keys_equal(it->first, value.first)) {
            return std::make_pair(it, false);
        }
        return std::make_pair(m_data.emplace(it, std::move(value)), true); // Throws
    }

    template <class P>
    std::pair<iterator, bool> insert(P pair)
    {
        return insert(value_type{std::get<0>(pair), std::get<1>(pair)});
    }

    template <class InputIt>
    void insert(InputIt first, InputIt last)
    {
        for (auto it = first; it != last; ++it) {
            insert(*it);
        }
    }

    template <class... Args>
    std::pair<iterator, bool> emplace(Args&&... args)
    {
        value_type value{std::forward<Args>(args)...};
        return insert(std::move(value));
    }

    template <class... Args>
    std::pair<iterator, bool> emplace_hint(const_iterator pos, Args&&... args)
    {
        static_cast<void>(pos); // FIXME: TODO
        return emplace(std::forward<Args>(args)...);
    }

    iterator erase(const_iterator pos) noexcept(std::is_nothrow_move_assignable<value_type>::value)
    {
        return m_data.erase(pos);
    }

    iterator erase(const_iterator first,
                   const_iterator last) noexcept(std::is_nothrow_move_assignable<value_type>::value)
    {
        return m_data.erase(first, last);
    }

    size_t erase(const K& key) noexcept(std::is_nothrow_move_assignable<value_type>::value)
    {
        auto it = find(key);
        if (it != end()) {
            erase(it);
            return 1;
        }
        return 0;
    }

    void swap(FlatMap& other)
    {
        m_data.swap(other.m_data);
    }

    template <class Key>
    size_t count(const Key& key) const noexcept
    {
        return find(key) == end() ? 0 : 1;
    }

    template <class Key>
    iterator find(const Key& key) noexcept
    {
        const FlatMap* This = this;
        const_iterator pos = This->find(key);
        return iterator{begin() + (pos - This->begin())};
    }

    template <class Key>
    const_iterator find(const Key& key) const noexcept
    {
        auto it = lower_bound(key);
        if (it == end() || !keys_equal(it->first, key)) {
            return end();
        }
        return it;
    }

    template <class Key>
    iterator lower_bound(const Key& key) noexcept
    {
        const FlatMap* This = this;
        const_iterator pos = This->lower_bound(key);
        return iterator{begin() + (pos - This->begin())};
    }

    template <class Key>
    const_iterator lower_bound(const Key& key) const noexcept
    {
        auto it = std::lower_bound(begin(), end(), key, [](const value_type& a, const Key& b) {
            return Cmp{}(a.first, b);
        });
        return it;
    }

    // FIXME: Not implemented yet.
    template <class Key>
    iterator upper_bound(const Key&) noexcept;
    // FIXME: Not implemented yet.
    template <class Key>
    const_iterator upper_bound(const Key&) const noexcept;

    void reserve(size_t size)
    {
        m_data.reserve(size); // Throws
    }

private:
    template <typename Lhs, typename Rhs>
    bool keys_equal(const Lhs& lhs, const Rhs& rhs) const
    {
        Cmp cmp{};
        return !cmp(lhs, rhs) && !cmp(rhs, lhs);
    }
    Container m_data;
};

} // namespace util
} // namespace realm

#endif // REALM_UTIL_FLAT_MAP_HPP
