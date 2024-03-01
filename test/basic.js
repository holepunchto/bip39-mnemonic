const test = require('brittle')
const b4a = require('b4a')

const { generateEntropy, generateMnemonic, mnemonicToSeed } = require('../')

const vectors = require('./vectors.json')

test('basic', async t => {
  const entropy = generateEntropy()

  t.unlike(entropy, b4a.alloc(32))

  const mnemonic = generateMnemonic()
  const seeded = generateMnemonic({ entropy })

  t.unlike(mnemonic, seeded)
  t.alike(seeded, generateMnemonic({ entropy }))

  const seed = await mnemonicToSeed(mnemonic)
  const otherSeed = await mnemonicToSeed(seeded)

  t.unlike(seed, b4a.alloc(32))
  t.unlike(otherSeed, b4a.alloc(32))
  t.unlike(seed, otherSeed)
})

test('vectors', async t => {
  for (const [language, vector] of Object.entries(vectors)) {
    t.comment(language)

    for (const [entropy, mnemonic, secret] of vector) {
      const words = generateMnemonic({
        entropy: b4a.from(entropy, 'hex'),
        language
      })

      t.is(words, mnemonic)

      const result = await mnemonicToSeed(mnemonic, 'TREZOR')
      t.is(b4a.toString(result, 'hex'), secret)
    }
  }
})
