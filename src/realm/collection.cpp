#include <realm/collection.hpp>
#include <realm/bplustree.hpp>
#include <realm/array_key.hpp>

namespace realm::_impl {

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

} // namespace realm::_impl
