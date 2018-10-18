local ffi    = require('ffi')
local log    = require('log')
local digest = require('digest')

local ibuf   = require('buffer').IBUF_SHARED

ffi.cdef[[
typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_signature;

typedef int (*secp256k1_nonce_function)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
);

/* Context and context creation */
struct secp256k1_context_struct;
typedef struct secp256k1_context_struct secp256k1_context;

secp256k1_context* secp256k1_context_create(unsigned int flags);
void secp256k1_context_destroy(secp256k1_context* ctx);

int secp256k1_ec_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_ec_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_pubkey* pubkey,
    unsigned int flags
);

int secp256k1_ecdsa_signature_parse_compact(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char *input64
);

int secp256k1_ecdsa_signature_serialize_compact(
    const secp256k1_context* ctx,
    unsigned char *output64,
    const secp256k1_ecdsa_signature* sig
);

int secp256k1_ecdsa_signature_parse_der(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_ecdsa_signature_serialize_der(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_ecdsa_signature* sig
);

int secp256k1_ecdsa_verify(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey
);

int secp256k1_ecdsa_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

int secp256k1_ec_seckey_verify(
    const secp256k1_context* ctx,
    const unsigned char *seckey
);

int secp256k1_ec_pubkey_create(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *seckey
);

int secp256k1_context_randomize(
    secp256k1_context* ctx,
    const unsigned char *seed32
);
]]

local secp256k1 = ffi.load('secp256k1')

local SECP256K1_FLAGS_TYPE_MASK          = bit.lshift(1, 8) - 1
local SECP256K1_FLAGS_TYPE_CONTEXT       = bit.lshift(1, 0)
local SECP256K1_FLAGS_TYPE_COMPRESSION   = bit.lshift(1, 1)
local SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = bit.lshift(1, 8)
local SECP256K1_FLAGS_BIT_CONTEXT_SIGN   = bit.lshift(1, 9)
local SECP256K1_FLAGS_BIT_COMPRESSION    = bit.lshift(1, 8)

local SECP256K1_CONTEXT_VERIFY = bit.bor(SECP256K1_FLAGS_TYPE_CONTEXT,
                                         SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
local SECP256K1_CONTEXT_SIGN   = bit.bor(SECP256K1_FLAGS_TYPE_CONTEXT,
                                         SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
local SECP256K1_CONTEXT_NONE   = bit.bor(SECP256K1_FLAGS_TYPE_CONTEXT)

local SECP256K1_EC_COMPRESSED   = bit.bor(SECP256K1_FLAGS_TYPE_COMPRESSION,
                                          SECP256K1_FLAGS_BIT_COMPRESSION)
local SECP256K1_EC_UNCOMPRESSED = bit.bor(SECP256K1_FLAGS_TYPE_COMPRESSION)

-------------------------------------------------------------------------------

local function secp256k1_gen_ctx(flags)
    local ctx = secp256k1.secp256k1_context_create(flags)
    assert(ctx, 'cp256k1_context_create failed')
    return ffi.gc(ctx, function(obj) log.info('destroyed'); secp256k1.secp256k1_context_destroy(obj) end)
end

local function secp256k1_ctx_verify(self, key)
    assert(#key == 32)
    return (secp256k1.secp256k1_ec_seckey_verify(self.int, key) == 1)
end

local secp256k1_ctx_mt = {
    __index = {
        verify = secp256k1_ctx_verify
    }
}

local function secp256k1_ctx_new(flags)
    local int = secp256k1_gen_ctx(flags)

    --[[
    if bit.band(flags, SECP256K1_FLAGS_BIT_CONTEXT_SIGN) ~= 0 then
        local seed = digest.urandom(32)
        local rv = secp256k1.secp256k1_context_randomize(int, seed)
        assert(rv == 1, 'cp256k1_context_randomize failed to execute')
    end
    ]]--

    return setmetatable({ int = int }, secp256k1_ctx_mt)
end

-------------------------------------------------------------------------------

local ctx        = secp256k1_ctx_new(SECP256K1_CONTEXT_NONE  )
local sign_ctx   = secp256k1_ctx_new(SECP256K1_CONTEXT_SIGN  )
local verify_ctx = secp256k1_ctx_new(SECP256K1_CONTEXT_VERIFY)

local static_size_t_buf = ffi.new('size_t [1]', 0)

-------------------------------------------------------------------------------

local function secp256k1_gen_signature()
    local signature_arr = ffi.new('secp256k1_ecdsa_signature [1]')
    assert(signature_arr)
    ffi.fill(signature_arr[1].data, 64, 0)
    return signature_arr
end

local function secp256k1_signature_tostring(self, opts)
    opts = opts or {}
    if opts.type == nil then
        opts.type = 'der'
    elseif opts.type ~= 'der' and opts.type ~= 'compact' then
        opts.type = 'der'
    end

    ibuf:recycle()
    static_size_t_buf[0] = 256
    local bpos = ibuf:alloc(256)

    local rv = nil
    if opts.type == 'der' then
        rv = secp256k1.secp256k1_ecdsa_signature_serialize_der(
            sign_ctx.int, bpos, static_size_t_buf, self.int
        )
    else
        rv = secp256k1.secp256k1_ecdsa_signature_serialize_compact(
            sign_ctx.int, bpos, self.int
        )
        static_size_t_buf[0] = 64
    end
    if rv == -1 then
        log.error('Failed to serialize signature')
        return nil
    end

    return ffi.string(bpos, tonumber(static_size_t_buf[0]))
end

local secp256k1_signature_mt = {
    __index = {
        tostring = secp256k1_signature_tostring,
    }
}

local function secp256k1_signature_new(input, opts)
    opts = opts or {}
    if opts.type == nil then
        opts.type = 'der'
    elseif opts.type ~= 'der' and opts.type ~= 'compact' then
        opts.type = 'der'
    end

    local self = {
        int = secp256k1_gen_signature()
    }
    if input then
        local rv = nil
        if opts.type == 'der' then
            rv = secp256k1.secp256k1_ecdsa_signature_parse_der(
                sign_ctx.int, self.int, input, #input
            )
        else
            rv = secp256k1.secp256k1_ecdsa_signature_parse_compact(
                sign_ctx.int, self.int, input
            )
        end
        if rv ~= 1 then
            log.error('Failed to parse compact signature: %s', input:hex())
            return nil
        end
    end
    return setmetatable(self, secp256k1_signature_mt)
end

-------------------------------------------------------------------------------

local function secp256k1_pubkey_verify(self, signature, hash)
    if type(signature) == 'str' then
        signature = secp256k1_signature_new(signature)
    end
    local rv = secp256k1.secp256k1_ecdsa_verify(
        verify_ctx.int, signature.int, hash, self.int
    )
    return rv == 1
end

local function secp256k1_pubkey_tostring(self, opts)
    opts = opts or {}
    if opts.compressed == nil then
        opts.compressed = true
    end
    local flags = opts.compressed and SECP256K1_EC_COMPRESSED
                                   or SECP256K1_EC_UNCOMPRESSED

    ibuf:recycle()
    static_size_t_buf[0] = 128;
    local bpos = ibuf:alloc(128)
    local rv = secp256k1.secp256k1_ec_pubkey_serialize(
        sign_ctx.int, bpos, static_size_t_buf, self.int, flags
    )
    if rv == -1 then
        log.error('Failed to serialize public key')
        return nil
    end
    return ffi.string(bpos, tonumber(static_size_t_buf[0]))
end

local secp256k1_pubkey_mt = {
    __index = {
        verify     = secp256k1_pubkey_verify,
        tostring   = secp256k1_pubkey_tostring,
        to_address = function(self) return self._address end,
        to_pkh     = function(self) return self._pkh     end,
    }
}

local function secp256k1_gen_pubkey()
    local pubkey_arr = ffi.new('secp256k1_pubkey [1]')
    ffi.fill(pubkey_arr[1].data, 64, 0)
    return pubkey_arr
end

local function secp256k1_pubkey_new(pubkey, tp)
    local self = setmetatable({
        int = secp256k1_gen_pubkey(),
    }, secp256k1_pubkey_mt)

    if #pubkey == 33 then -- public key
        local rv = secp256k1.secp256k1_ec_pubkey_parse(
            sign_ctx.int, self.int, pubkey, #pubkey
        )
        if rv ~= 1 then
            return nil
        end
    elseif #pubkey == 32 then -- generate from private key
        local rv = secp256k1.secp256k1_ec_pubkey_create(
            sign_ctx.int, self.int, pubkey
        )
        if rv ~= 1 then
            return nil
        end
    else
        assert(false)
    end

    return self
end

-------------------------------------------------------------------------------

local function secp256k1_privkey_sign(self, hash)
    local signature = secp256k1_signature_new()

    local rv = secp256k1.secp256k1_ecdsa_sign(
        sign_ctx.int, signature.int, hash, self.privkey, nil, nil
    )
    if rv ~= 1 then
        return nil
    end

    return signature
end

local secp256k1_privkey_mt = {
    __index = {
        sign     = secp256k1_privkey_sign,
        tostring = function(self)      return self.privkey            end,
        verify   = function(self, ...) return self.pubkey:verify(...) end,
    }
}

local function secp256k1_privkey_new(privkey)
    local self = { }
    if privkey == nil then -- generate private key
        repeat
            privkey = digest.urandom(32)
        until sign_ctx:verify(privkey)
    end
    self.privkey = privkey
    self.pubkey  = secp256k1_pubkey_new(privkey)
    return setmetatable(self, secp256k1_privkey_mt)
end

-------------------------------------------------------------------------------

return {
    signature     = secp256k1_signature_new,
    public_key    = secp256k1_pubkey_new,
    private_key   = secp256k1_privkey_new,
}
