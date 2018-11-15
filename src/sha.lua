local SHA = {};




---
--@param #string bytes the bytes to read from
local function bytesToWord(bytes)
  if #bytes == 0 then
    return
  end
  local a,b,c,d = bytes:byte(1,4);
  return bit32.bor(bit32.lshift(a,24),bit32.lshift(b,16),bit32.lshift(c,8),d),bytesToWord(bytes:sub(5));
end


local function wordsToBytes(word,...)
  if not word then
    return
  end
  local a,b,c,d;
  a = bit32.rshift(word,24);
  b = bit32.band(bit32.rshift(w,16),0xff);
  c = bit32.band(bit32.rshift(w,8),0xff);
  d = bit32.band(w,0xff);
  return string.char(a,b,c,d),wordsToBytes(...);
end

local function zeros(count)
  if count ~= 0 then
    return 0,zeros(count-1)
  end
end

local function dwordToBytes(dword)
  return wordToBytes(math.floor(dword/(2^32)))..wordToBytes(dword%(2^32));
end

local function limit(a)
  return a%(2^32);
end

local k = 
  {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

---
--@param #string mem
--@param #number h0,h1,h2,h3,h4,h5,h6,h7
local function SHA2_1(mem,h0,h1,h2,h3,h4,h5,h6,h7)
  local len = #mem;
  local nzeros = 64-((mem+9)%64);
  local tlen = len+nzeros;
  mem = mem..string.byte(0x80,zeros(nzeros))..dwordToBytes(len*8);
  local nblocks = math.floor(tlen/64)+1;
  
  for b=1,nblocks do
    local w = {wordsToBytes(mem:sub(1,64))};
    mem = mem:sub(65);
    for q=17,64 do
      local s0 = bit32.bxor(bit32.rrotate(w[q-15],7),bit32.rrotate(w[q-15],18),bit32.rshift(w[q-15],3));
      local s1 = bit32.bxor(bit32.rrotate(w[q-2],17),bit32.rrotate(w[q-2],19),bit32.rshift(w[q-2],10));
      w[q] = limit(s0 + w[q-16] + s1 + w[q-7]);
    end
    local a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7;
    for q=1,64 do
      local S1 = bit32.bxor(bit32.rrotate(e,6),bit32.rrotate(e,11),bit32.rrotate(e,25));
      local ch = bit32.bxor(bit32.band(e,f),bit32.band(bit32.bnot(e),g));
      local tmp1 = limit(h + S1 + ch + w[q] + k[q]);
      local S0 = bit32.bxor(bit32.rrotate(a,2),bit32.rrotate(a,13),bit32.rrotate(a,22));
      local maj = bit32.bxor(bit32.band(a,b),bit32.band(a,c),bit32.band(b,c));
      local tmp2 = limit(S0 + maj);
      h = g;
      g = f;
      f = e;
      e = limit(d+tmp1);
      d = c;
      c = b;
      b = a;
      a = limit(tmp1+tmp2);
    end
    h0 = limit(h0 + a);
    h1 = limit(h1 + b);
    h2 = limit(h2 + c);
    h3 = limit(h3 + d);
    h4 = limit(h4 + e);
    h5 = limit(h5 + f);
    h6 = limit(h6 + g);
    h7 = limit(h7 + h);
  end
  return h0,h1,h2,h3,h4,h5,h6,h7;
end

function SHA.SHA224(mem)
  local h0,h1,h2,h3,h4,h5,h6 = SHA2_1(mem,0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4);
  return wordsToBytes(h0,h1,h2,h3,h4,h5,h6);
end

function SHA.SHA256(mem)
  return wordsToBytes(SHA2_1(mem,0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19));
end

return SHA;

