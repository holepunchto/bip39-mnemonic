const test = require('brittle')
const b4a = require('b4a')

const { generateMnemonic } = require('../')

const vectors = require('./vectors.json')

test('vectors', t => {
  for (const [language, vector] of Object.entries(vectors)) {
    t.comment(language)

    for (const [seed, mnemonic] of vector) {
      const result = generateMnemonic(b4a.from(seed, 'hex'), language)
      t.is(result, mnemonic)
    }
  }
})
