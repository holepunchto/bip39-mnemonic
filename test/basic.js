const test = require('brittle')
const b4a = require('b4a')

const {
  generateEntropy,
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed
} = require('../')

const vectors = require('./vectors.json')

test('basic', async t => {
  const entropy = generateEntropy()

  t.unlike(entropy, b4a.alloc(32))

  const mnemonic = generateMnemonic()
  const seeded = generateMnemonic({ entropy })

  t.unlike(mnemonic, seeded)
  t.alike(seeded, generateMnemonic({ entropy }))

  t.ok(validateMnemonic(mnemonic))
  t.ok(validateMnemonic(seeded))

  const seed = await mnemonicToSeed(mnemonic)
  const otherSeed = await mnemonicToSeed(seeded)

  t.unlike(seed, b4a.alloc(32))
  t.unlike(otherSeed, b4a.alloc(32))
  t.unlike(seed, otherSeed)
})

test('vectors', async t => {
  for (const [language, vector] of Object.entries(vectors)) {
    if (language !== 'english') continue
    t.comment(language)

    for (const [entropy, mnemonic, secret] of vector) {
      const words = generateMnemonic({
        entropy: b4a.from(entropy, 'hex'),
        language
      })

      t.is(words, mnemonic)
      t.ok(validateMnemonic(mnemonic, { language }))

      const result = await mnemonicToSeed(mnemonic, 'TREZOR')
      t.is(b4a.toString(result, 'hex'), secret)
    }
  }
})

test('invalid mnemonic', async t => {
  const words = generateMnemonic().split(' ')

  t.ok(validateMnemonic(words.join(' ')))
  t.absent(validateMnemonic(words.reverse().join(' ')))

  await t.exception(() => mnemonicToSeed(words.join(' ')))

  words.reverse()[0] = 'rrrrrr'

  t.absent(validateMnemonic(words.join(' ')))

  words.fill('notaword')
  t.absent(validateMnemonic(words.join(' ')))
})
