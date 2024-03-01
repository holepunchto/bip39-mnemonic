const sodium = require('sodium-universal')
const b4a = require('b4a')
const assert = require('nanoassert')
const pbkdf2 = require('@holepunchto/pbkdf2')
const loadWordlist = require('./wordlist')

module.exports = {
  generateEntropy,
  generateMnemonic,
  mnemonicToSeed
}

function generateMnemonic ({ entropy = generateEntropy(), language = 'english' } = {}) {
  const wordlist = loadWordlist(language)
  const extended = computeCheckSum(entropy)

  const words = []

  for (const index of uint11Reader(extended)) {
    words.push(wordlist[index])
  }

  const delimiter = language === 'japanese' ? '\u3000' : ' '

  return words.join(delimiter).trim()
}

function mnemonicToSeed (mnemonic, passphrase = '') {
  const input = b4a.from(mnemonic.replace(/\u3000/g, ' '))
  const salt = b4a.from('mnemonic' + passphrase)

  return pbkdf2({
    password: input,
    salt,
    iterations: 2048,
    length: 64,
    hash: 'sha512'
  })
}

function sha256 (data, output = b4a.alloc(32)) {
  sodium.crypto_hash_sha256(output, data)
  return output
}

function computeCheckSum (seed) {
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

function generateEntropy (length = 32) {
  const seed = b4a.alloc(length)
  sodium.randombytes_buf(seed)

  return seed
}

function * uint11Reader (state) {
  yield * uintReader(state, 11)
}

function * uintReader (buffer, width) {
  const MASK = (2 << (width - 1)) - 1

  let pos = 0
  let value = 0

  while (true) {
    const offset = pos >> 3 // byte offset

    if (offset >= buffer.byteLength) {
      return value & MASK
    }

    const height = width - (pos % width)
    const leftover = (offset + 1) * 8 - pos

    value += shift(buffer[offset], height - leftover)

    pos += Math.min(height, leftover)
    if (pos % width) continue

    yield value & MASK

    value = 0
  }
}

// when n is positive, shift left n bits
// when n is negative, shift right -n bits
function shift (val, n) {
  if (n === 0) return val
  if (n > 0) return val << n

  return val >> (-1 * n)
}
