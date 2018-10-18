local log      = require('log')
local digest   = require('digest')

local internal = require('secp256k1.internal')

-------------------------------------------------------------------------------

local function secp256k1_signature_tostring(self, opts)
    opts = opts or {}
    if opts.type == nil then
        opts.type = 'der'
    elseif opts.type ~= 'der' and opts.type ~= 'compact' then
        opts.type = 'der'
    end

    local rv = nil
    if opts.type == 'der' then
        rv = internal.ecdsa_signature_serialize_der(self.int)
    else
        rv = internal.ecdsa_signature_serialize_compact(self.int)
    end
    if not rv then
        log.error('Failed to serialize signature')
        return nil
    end

    return rv
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

    local self = { int = internal.int_signature_new() }
    if input then
        local rv = nil
        if opts.type == 'der' then
            rv = internal.ecdsa_signature_parse_der(self.int, input)
        else
            rv = internal.ecdsa_signature_parse_compact(self.int, input)
        end
        if not rv then
            log.error('Failed to parse signature: %s', input:hex())
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
    return internal.ecdsa_verify(signature.int, hash, self.int)
end

local function secp256k1_pubkey_tostring(self, opts)
    opts = opts or {}
    if opts.compressed == nil then
        opts.compressed = true
    end
    local flags = opts.compressed and 1 or 0

    local rv = internal.ec_pubkey_serialize(self.int, flags)
    if not rv then
        log.error('Failed to serialize public key')
        return nil
    end
    return rv
end

local secp256k1_pubkey_mt = {
    __index = {
        verify     = secp256k1_pubkey_verify,
        tostring   = secp256k1_pubkey_tostring,
        to_address = function(self) return self._address end,
        to_pkh     = function(self) return self._pkh     end,
    }
}

local function secp256k1_pubkey_new(pubkey, tp)
    local self = setmetatable({
        int = internal.int_pubkey_new()
    }, secp256k1_pubkey_mt)

    local rv = nil
    if #pubkey == 33 then -- public key
        rv = internal.ec_pubkey_parse(self.int, pubkey)
    elseif #pubkey == 32 then -- generate from private key
        rv = internal.ec_pubkey_create(self.int, pubkey)
    else
        assert(false)
    end
    if not rv then
        log.error('Failed to create pubkey')
        return nil
    end

    return self
end

-------------------------------------------------------------------------------

local function secp256k1_privkey_sign(self, hash)
    local signature = secp256k1_signature_new()

    local rv = internal.ecdsa_sign(signature.int, hash, self.privkey)
    if not rv then
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
        until internal.ec_seckey_verify(privkey)
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
