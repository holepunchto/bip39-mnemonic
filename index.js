const sodium = require('sodium-universal')
const b4a = require('b4a')
const assert = require('nanoassert')
const { detectLanguage, loadWordlist } = require('./wordlist')

module.exports = {
  generateEntropy,
  generateMnemonic,
  normalizeMnemonic,
  validateMnemonic,
  mnemonicToEntropy,
  mnemonicToSeed,
  entropyToMnemonic
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

function entropyToMnemonic (entropy, { language = 'english' } = {}) {
  return generateMnemonic({ entropy, language })
}

function mnemonicToEntropy (mnemonic) {
  const words = mnemonic.replace(/\u3000/g, ' ').trim().split(' ')
  const language = detectLanguage(words)

  if (!language) {
    throw new Error('Language not recognised')
  }

  if (words.length % 3 !== 0) {
    throw new Error('Invalid length')
  }

  const wordlist = loadWordlist(language)

  const indexes = []
  for (const word of words) {
    const index = wordlist.indexOf(word)
    if (index === -1) {
      throw new Error('Bad word')
    }

    indexes.push(index)
  }

  const bits = words.length * 11
  const len = (bits * 32 / 33) >> 3

  const extended = b4a.alloc(Math.ceil(bits / 8))
  const entropy = extended.subarray(0, len)

  uint11Writer(extended, indexes)

  if (!b4a.equals(extended, computeCheckSum(entropy))) {
    throw new Error('Invalid checksum')
  }

  return entropy
}

function normalizeMnemonic (mnemonic) {
  return mnemonic.trim().replace(/\u3000/, ' ').split(/\s+/).map(c => c.toLowerCase()).join(' ')
}

async function mnemonicToSeed (mnemonic, passphrase = '') {
  mnemonic = normalizeMnemonic(mnemonic)

  if (!validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic')
  }

  const input = b4a.from(mnemonic)
  const salt = b4a.from('mnemonic' + passphrase)

  const output = b4a.alloc(64)

  await sodium.extension_pbkdf2_sha512_async(
    output,
    input,
    salt,
    2048,
    64
  )

  return output
}

function validateMnemonic (mnemonic) {
  try {
    mnemonicToEntropy(mnemonic)
  } catch (e) {
    return false
  }
  return true
}

function sha256 (data, output = b4a.alloc(32)) {
  sodium.crypto_hash_sha256(output, data)
  return output
}

function computeCheckSum (seed) {
  assert((seed.byteLength & 4) === 0, 'seed must be a multiple of 4 bytes')

  const len = seed.byteLength
  const cklen = len >> 2 // cksum bits
  const total = len + Math.ceil(cklen / 8)

  const output = b4a.alloc(len + 32)
  output.set(seed)

  const entropy = output.subarray(0, len)
  const cksum = output.subarray(len)

  sha256(entropy, cksum)

  // only append cklen bits
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

function uint11Writer (buf, uints) {
  return uintWriter(buf, uints, 11)
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

function uintWriter (buffer, uints, width) {
  let pos = 0

  while (true) {
    const offset = pos >> 3 // byte offset

    const i = Math.floor(pos / width)
    if (i >= uints.length) break

    if (offset >= buffer.length) {
      throw new Error('Failed to encode uints')
    }

    const rem = 8 - pos % 8
    const height = (i + 1) * width - pos

    const value = shift(uints[i], rem - height)

    buffer[offset] += mask(value, rem)

    pos += Math.min(rem, height)
  }

  return buffer
}

// when n is positive, shift left n bits
// when n is negative, shift right -n bits
function shift (val, n) {
  if (n === 0) return val
  if (n > 0) return val << n

  return val >> (-1 * n)
}

function mask (val, bits) {
  if (bits < 32) return val & ((1 << bits) - 1)
  return val % (2 ** bits)
}
