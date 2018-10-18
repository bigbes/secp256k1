package = 'secp256k1'
version = 'scm-1'
source  = {
    url    = 'git://github.com/bigbes/secp256k1.git',
    branch = 'master',
}
description = {
    summary  = "Secp256k1 wrappers for Tarantool",
    homepage = 'https://github.com/bigbes/secp256k1/',
    license  = 'BSD',
    maintainer = "Eugene Blikh <bigbes@gmail.com>";

}
dependencies = {
    'lua >= 5.1'
}
build = {
    type = 'cmake';
    variables = {
        CMAKE_BUILD_TYPE="RelWithDebInfo";
        TARANTOOL_DIR='$(TARANTOOL_DIR)',
        TARANTOOL_INSTALL_LIBDIR="$(LIBDIR)";
        TARANTOOL_INSTALL_LUADIR="$(LUADIR)";
    };
}

-- vim: syntax=lua
