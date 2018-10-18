#include <module.h> /* <tarantool/module.h> */

#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <stdarg.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <secp256k1.h>

static secp256k1_context *context;
static secp256k1_context *sign_context;
static secp256k1_context *verify_context;

static const char pubkey_typename[]    = "secp256k1.pubkey";
static const char signature_typename[] = "secp256k1.signature";

LUA_API int
Tsecp256k1_int_signature_new(lua_State *L)
{
	void *p = lua_newuserdata(L, sizeof(secp256k1_ecdsa_signature) * 2);
	memset(p, 0, sizeof(secp256k1_ecdsa_signature));
	luaL_getmetatable(L, signature_typename);
	lua_setmetatable(L, -2);
	return 1;
}

LUA_API int
Tsecp256k1_int_pubkey_new(lua_State *L)
{
	void *p = lua_newuserdata(L, sizeof(secp256k1_pubkey) * 2);
	memset(p, 0, sizeof(secp256k1_pubkey));
	luaL_getmetatable(L, pubkey_typename);
	lua_setmetatable(L, -2);
	return 1;
}

/* 
 * <- pubkey (string), pubkey (udata)
 * -> true / false
 */
LUA_API int
Tsecp256k1_ec_pubkey_parse(lua_State *L)
{
	secp256k1_pubkey *pubkey_obj = luaL_checkudata(L, 1, pubkey_typename);
	size_t pubkey_len = 0;
	const unsigned char *pubkey;
	pubkey = (const unsigned char *)luaL_checklstring(L, 2, &pubkey_len);

	int rv = secp256k1_ec_pubkey_parse(context, pubkey_obj,
					   pubkey, pubkey_len);

	lua_pushboolean(L, rv);
	return 1;
}

/*
 * <- pubkey (udata), is_compressed (int, opt == 1)
 * -> string / false
 */
LUA_API int
Tsecp256k1_ec_pubkey_serialize(lua_State *L) {
	secp256k1_pubkey *pubkey_obj = luaL_checkudata(L, 1, pubkey_typename);

	int flags = SECP256K1_EC_COMPRESSED;
	if (luaL_optnumber(L, 2, 1) == 0) {
		flags = SECP256K1_EC_UNCOMPRESSED;
	}

	unsigned char pubkey[66]; size_t pubkey_len = 66;
	int rv = secp256k1_ec_pubkey_serialize(context,
			(unsigned char *)pubkey, &pubkey_len, pubkey_obj, flags);
	if (rv == 1) {
		lua_pushlstring(L, (const char *)pubkey, pubkey_len);
		return 1;
	}
	return 0;
}

/*
 * <- signature (udata), input (string)
 * -> true / false
 */
LUA_API int
Tsecp256k1_ecdsa_signature_parse_compact(lua_State *L) {
	secp256k1_ecdsa_signature *signature_obj;
	signature_obj = luaL_checkudata(L, 1, signature_typename);

	size_t signature_len = 0;
	const unsigned char *signature;
	signature = (const unsigned char *)luaL_checklstring(L, 2, &signature_len);
	assert(signature_len == 64);

	int rv = secp256k1_ecdsa_signature_parse_compact(context, signature_obj,
							 signature);

	lua_pushboolean(L, rv);
	return 1;
}

/*
 * <- signature (udata), input (string)
 * -> true / false
 */
LUA_API int
Tsecp256k1_ecdsa_signature_parse_der(lua_State *L) {
	secp256k1_ecdsa_signature *signature_obj;
	signature_obj = luaL_checkudata(L, 1, signature_typename);

	size_t signature_len = 0;
	const unsigned char *signature;
	signature = (const unsigned char *)luaL_checklstring(L, 2, &signature_len);

	int rv = secp256k1_ecdsa_signature_parse_der(context, signature_obj,
						     signature, signature_len);

	lua_pushboolean(L, rv);
	return 1;
}

/*
 * <- signature (udata)
 * -> string / false
 */
LUA_API int
Tsecp256k1_ecdsa_signature_serialize_der(lua_State *L) {
	secp256k1_ecdsa_signature *signature_obj;
	signature_obj = luaL_checkudata(L, 1, signature_typename);

	size_t signature_len = 128; unsigned char signature[128];

	int rv = secp256k1_ecdsa_signature_serialize_der(
			context, signature, &signature_len, signature_obj);

	if (rv == 1) {
		lua_pushlstring(L, (const char *)signature, signature_len);
		return 1;
	}
	return 0;
}

/*
 * <- signature (udata)
 * -> string / false
 */
LUA_API int
Tsecp256k1_ecdsa_signature_serialize_compact(lua_State *L) {
	secp256k1_ecdsa_signature *signature_obj;
	signature_obj = luaL_checkudata(L, 1, signature_typename);

	size_t signature_len = 64;
	unsigned char signature[64];

	int rv = secp256k1_ecdsa_signature_serialize_compact(
			context, signature, signature_obj);

	if (rv == 1) {
		lua_pushlstring(L, (const char *)signature, signature_len);
		return 1;
	}
	return 0;
}

/*
 * <- signature (udata), hash(string, 32bytes), pubkey (udata)
 * -> true / false
 */
LUA_API int
Tsecp256k1_ecdsa_verify(lua_State *L) {
	secp256k1_pubkey *pubkey_obj;
	secp256k1_ecdsa_signature *signature_obj;
	size_t hash32_len; const unsigned char *hash32;

	signature_obj = luaL_checkudata(L, 1, signature_typename);
	hash32 = (const unsigned char *)luaL_checklstring(L, 2, &hash32_len);
	pubkey_obj = luaL_checkudata(L, 3, pubkey_typename);

	int rv = secp256k1_ecdsa_verify(verify_context, signature_obj, hash32,
					pubkey_obj);

	lua_pushboolean(L, rv);
	return 1;
}

/*
 * <- signature (udata), hash(string, 32bytes), seckey
 * -> true / false
 */
LUA_API int
Tsecp256k1_ecdsa_sign(lua_State *L) {
	secp256k1_ecdsa_signature *signature_obj;
	size_t privkey_len, hash32_len; const unsigned char *hash32, *privkey;

	signature_obj = luaL_checkudata(L, 1, signature_typename);
	hash32 = (const unsigned char *)luaL_checklstring(L, 2, &hash32_len);
	privkey = (const unsigned char *)luaL_checklstring(L, 3, &privkey_len);

	int rv = secp256k1_ecdsa_sign(sign_context, signature_obj, hash32,
				      privkey, NULL, NULL);

	lua_pushboolean(L, rv);
	return 1;
}

/*
 * <- private key(string, 32 bytes)
 * -> true / false
 */
LUA_API int
Tsecp256k1_ec_seckey_verify(lua_State *L) {
	size_t privkey_len; const unsigned char *privkey;
	privkey = (const unsigned char *)luaL_checklstring(L, 1, &privkey_len);

	int rv = secp256k1_ec_seckey_verify(sign_context, privkey);

	lua_pushboolean(L, rv);
	return 1;
}

/*
 * <- public (udata), private(string, 32 bytes)
 * -> true / false
 */
LUA_API int
Tsecp256k1_ec_pubkey_create(lua_State *L) {
	secp256k1_pubkey *pubkey_obj;
	size_t privkey_len; const unsigned char *privkey;

	pubkey_obj = luaL_checkudata(L, 1, pubkey_typename);
	privkey = (const unsigned char *)luaL_checklstring(L, 2, &privkey_len);

	int rv = secp256k1_ec_pubkey_create(sign_context, pubkey_obj, privkey);

	lua_pushboolean(L, rv);
	return 1;
}

void secp256k1_handler(const char *message, void *data) {
	(void )data;
	say_error(message);
}

LUA_API int
luaopen_secp256k1_internal(lua_State *L)
{

	context        = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	sign_context   = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	verify_context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	assert(context && sign_context && verify_context);

	#if 0
	secp256k1_context_set_error_callback(context,          &secp256k1_handler, NULL);
	secp256k1_context_set_error_callback(sign_context,     &secp256k1_handler, NULL);
	secp256k1_context_set_error_callback(verify_context,   &secp256k1_handler, NULL);
	secp256k1_context_set_illegal_callback(context,        &secp256k1_handler, NULL);
	secp256k1_context_set_illegal_callback(sign_context,   &secp256k1_handler, NULL);
	secp256k1_context_set_illegal_callback(verify_context, &secp256k1_handler, NULL);
	#endif

	static const struct luaL_Reg signature_meta[] = {
		{NULL, NULL}
	};
	luaL_newmetatable(L, signature_typename);
	lua_pushstring(L, signature_typename);
	lua_setfield(L, -2, "__metatable");
	luaL_register(L, NULL, signature_meta);
	lua_pop(L, 1);

	static const struct luaL_Reg pubkey_meta[] = {
		{NULL, NULL}
	};
	luaL_newmetatable(L, pubkey_typename);
	lua_pushstring(L, pubkey_typename);
	lua_setfield(L, -2, "__metatable");
	luaL_register(L, NULL, pubkey_meta);
	lua_pop(L, 1);

	lua_newtable(L);
	static const struct luaL_Reg funcs[] = {
		{ "int_signature_new",                 Tsecp256k1_int_signature_new                 },
		{ "int_pubkey_new",                    Tsecp256k1_int_pubkey_new                    },
		{ "ec_pubkey_parse",                   Tsecp256k1_ec_pubkey_parse                   },
		{ "ec_pubkey_serialize",               Tsecp256k1_ec_pubkey_serialize               },
		{ "ecdsa_signature_parse_compact",     Tsecp256k1_ecdsa_signature_parse_compact     },
		{ "ecdsa_signature_parse_der",         Tsecp256k1_ecdsa_signature_parse_der         },
		{ "ecdsa_signature_serialize_der",     Tsecp256k1_ecdsa_signature_serialize_der     },
		{ "ecdsa_signature_serialize_compact", Tsecp256k1_ecdsa_signature_serialize_compact },
		{ "ecdsa_verify",                      Tsecp256k1_ecdsa_verify                      },
		{ "ecdsa_sign",                        Tsecp256k1_ecdsa_sign                        },
		{ "ec_seckey_verify",                  Tsecp256k1_ec_seckey_verify                  },
		{ "ec_pubkey_create",                  Tsecp256k1_ec_pubkey_create                  },
		{ NULL,                                NULL                                         }
	};
	luaL_register(L, NULL, funcs);

	return 1;
}
