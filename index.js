const fs = require('fs')
const path = require('path')
const sodium = require('sodium-universal')
const b4a = require('b4a')
const assert = require('nanoassert')

module.exports = {
  generateSeed,
  generateMnemonic
}

function generateSeed (length = 32) {
  const seed = b4a.alloc(length)
  sodium.randombytes_buf(seed)

  return seed
}

function loadWordlist (language) {
  const file = path.resolve(__dirname, 'wordlist', language + '.txt')
  const words = fs.readFileSync(file, 'utf8')

  return words.split('\n')
}

function generateMnemonic (seed, language = 'english') {
  const wordlist = loadWordlist(language)
  const entropy = generateEntropy(seed)

  const bitlen = entropy.byteLength * 8
  const indices = new Array(Math.floor(bitlen / 11))

  indices.fill(0)

  let pos = 0

  for (let i = 0; i < entropy.length; i++) {
    const byte = entropy[i]

    const idx = Math.floor((i * 8) / 11)
    const bitpos = 11 - ((i * 8) % 11)

    indices[idx] += shift(byte, bitpos - 8)

    if (bitpos >= 8 || idx === indices.length - 1) continue

    const mask = (2 << (7 - bitpos)) - 1
    const right = (byte & mask) << (3 + bitpos)
    indices[idx + 1] += (byte & mask) << (3 + bitpos)

    pos += 8
  }

  const words = indices.map(i => wordlist[i])
  const delimiter = language === 'japanese' ? '\u3000' : ' '

  return words.join(delimiter).trim()
}

function sha256 (data, output = b4a.alloc(32)) {
  sodium.crypto_hash_sha256(output, data)
  return output
}

function generateEntropy (seed) {
  assert((seed.byteLength & 4) === 0, 'seed must be a multiple of 4 bytes')

  const len = seed.byteLength
  const cklen = len >> 2
  const total = len + (cklen >> 3) + 1

  const output = b4a.alloc(len + 32)
  output.set(seed)

  const entropy = output.subarray(0, len)
  const cksum = output.subarray(len)
  
  sha256(entropy, cksum)

  output[total - 1] &= (0xff ^ (0xff >> cklen))
  return output.subarray(0, total)
}

// when n is positive, shift left n bits
// when n is negative, shift right -n bits
function shift (val, n) {
  if (n === 0) return val
  if (n > 0) return val << n

  return val >> (-1 * n)
}

function umask (bits) {
  return (0xff >> bits) << bits
}
