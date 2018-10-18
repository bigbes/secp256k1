# Build
if (APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -undefined suppress -flat_namespace")
endif(APPLE)

add_library(internalso SHARED internal.c)
target_link_libraries(internalso LINK_PUBLIC "${Secp256k1_LIBRARY}")
target_link_libraries(internalso LINK_PRIVATE "-lgmp")
set_target_properties(internalso
    PROPERTIES
        PREFIX ""
        SUFFIX ".so"
        OUTPUT_NAME "internal")

# Install
install(TARGETS internalso LIBRARY DESTINATION ${TARANTOOL_INSTALL_LIBDIR}/${PROJECT_NAME})
install(FILES init.lua             DESTINATION ${TARANTOOL_INSTALL_LUADIR}/${PROJECT_NAME})

