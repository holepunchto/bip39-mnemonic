const test = require('brittle')
const b4a = require('b4a')

const { generateMnemonic, mnemonicToSeed } = require('../')

const vectors = require('./vectors.json')

test('vectors', t => {
  for (const [language, vector] of Object.entries(vectors)) {
    t.comment(language)

    for (const [seed, mnemonic, secret] of vector) {
      const words = generateMnemonic(b4a.from(seed, 'hex'), language)
      t.is(words, mnemonic)

      const result = mnemonicToSeed(mnemonic, 'TREZOR')
      t.is(b4a.toString(result, 'hex'), secret)
    }
  }
})
