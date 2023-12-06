file(GLOB BSON_SRC CONFIGURE_DEPENDS "*.h" "*.c")

add_library(Bson STATIC ${BSON_SRC})
add_library(Realm::Bson ALIAS Bson)
target_compile_definitions(Bson PRIVATE _GNU_SOURCE BSON_COMPILATION)
target_include_directories(Bson PUBLIC ..)
