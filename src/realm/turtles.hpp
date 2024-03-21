#include "realm/alloc.hpp"
#include "realm/node.hpp"

#ifndef REALM_TURTLES_HPP
#define REALM_TURTLES_HPP

namespace realm {

class Turtles : public Node {
public:
    Turtles(Allocator& alloc);
    void init_from_parent();
    void init_from_ref(ref_type ref);
    void set(size_t index, int64_t value);
};

} // namespace realm
#endif
