const fs = require('fs')
const path = require('path')
const sodium = require('sodium-universal')
const b4a = require('b4a')
const assert = require('nanoassert')

module.exports = {
  generateSeed,
  generateMnemonic
}

const MAX_UINT11 = 0b11111111111

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

  const words = []

  const state = { buffer: entropy, offset: 0, value: 0 }

  while (true) {
    const index = readUInt11(state)
    if (index === -1) break

    words.push(wordlist[index])
  }

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

function readUInt11 (state) {
  const idx = state.offset / 8
  if (idx >= state.buffer.byteLength) return -1

  const byte = state.buffer[idx]
  const height = 11 - (state.offset % 11) // height of leading bit

  state.offset += 8
  state.value += shift(byte, height - 8)

  const value = state.value & MAX_UINT11

  if (height > 8) return readUInt11(state)

  state.value = 0
  if (height === 8) return value

  // shift bottom limb by (11 - (8 - height))
  state.value = shift(byte, 3 + height)

  return value
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
