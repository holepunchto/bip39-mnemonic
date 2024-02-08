const fs = require('fs')
const path = require('path')
const sodium = require('sodium-universal')
const b4a = require('b4a')
const assert = require('nanoassert')
const { pbkdf2, sha512 } = require('@holepunchto/pbkdf2')

module.exports = {
  generateSeed,
  generateMnemonic,
  mnemonicToSeed
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

  const words = []
  for (const index of uint11Reader(entropy)) {
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
    hash: sha512
  })
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

function uint11Reader (state) {
  return uintReader(state, 11)
}

function * uintReader (buffer, width) {
  const MAX_UINT = (2 << (width - 1)) - 1

  let pos = 0
  let value = 0

  while (true) {
    const offset = pos >> 3 // byte offset

    if (offset >= buffer.byteLength) return value
    const byte = buffer[offset]

    const leftover = (offset + 1) * 8 - pos
    const height = width - (pos % width)

    const read = Math.min(height, leftover)

    pos += read
    value += shift(byte, height - leftover)

    if (pos % width) continue

    yield value & MAX_UINT
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
