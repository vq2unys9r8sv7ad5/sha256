local byte = string.byte
local char = string.char
local format = string.format
local gsub = string.gsub
local rep = string.rep
local band = bit32.band
local bnot = bit32.bnot
local bxor = bit32.bxor
local rrotate = bit32.rrotate
local rshift = bit32.rshift

local Primes = {
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2
}

local function Hex(String)
    local Result = gsub(String,".",function(Character)
        return format("%02x",byte(Character))
    end)
    
    return Result
end

local function Bytes(Value,Length)
    local String = ""
    
    for i = 1,Length do
        local Remaining = Value % 256
        
        String = char(Remaining)..String
        Value = (Value - Remaining) / 256
    end
    
    return String
end

local function ReadInt32(Buffer,Index)
    local Value = 0
    
    for i = Index,Index + 3 do 
        Value = (Value * 256) + byte(Buffer,i)
    end
    
    return Value
end

local function DigestBlock(Text,Index,Hash)
    local Digest = {}
    
    for i = 1,16 do 
        Digest[i] = ReadInt32(Text,Index + (i - 1) * 4) 
    end
    
    for i = 17,64 do
        local v = Digest[i - 15]
        local s0 = bxor(rrotate(v,7),rrotate(v,18),rshift(v,3))
        
        v = Digest[i - 2]
        Digest[i] = Digest[i - 16] + s0 + Digest[i - 7] + bxor(rrotate(v,17),rrotate(v,19),rshift(v,10))
    end
    
    local a,b,c,d,e,f,g,h = unpack(Hash)
    
    for i = 1,64 do
        local s0 = bxor(rrotate(a,2),rrotate(a,13),rrotate(a,22))
        local maj = bxor(band(a,b),band(a,c),band(b,c))
        
        local t2 = s0 + maj
        local s1 = bxor(rrotate(e,6),rrotate(e,11),rrotate(e,25))
        
        local ch = bxor(band(e,f),band(bnot(e),g))
        local t1 = h + s1 + ch + Primes[i] + Digest[i]
        
        h,g,f,e,d,c,b,a = g,f,e,d + t1,c,b,a,t1 + t2
    end
    
    Hash[1] = band(Hash[1] + a)
    Hash[2] = band(Hash[2] + b)
    Hash[3] = band(Hash[3] + c)
    Hash[4] = band(Hash[4] + d)
    Hash[5] = band(Hash[5] + e)
    Hash[6] = band(Hash[6] + f)
    Hash[7] = band(Hash[7] + g)
    Hash[8] = band(Hash[8] + h)
end

return function(Text)
    Text = tostring(Text)
    
    do
        local Extra = 64 - (#Text + 9 % 64)
        local Length = Bytes(8 * #Text,8)
        
        Text = Text.."\128"..rep("\0",Extra)..Length
        
        if #Text % 64 ~= 0 then
            return ""
        end
    end
    
    local Hash = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    }
    
    for i = 1,#Text,64 do 
        DigestBlock(Text,i,Hash)
    end
    
    local Result = ""
    
    for i = 1,8 do
        local v = Hash[i]
        
        Result = Result..Bytes(v,4)
    end
    
    return Hex(Result)
end
