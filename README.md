# bip39-mnemonic

## Usage

```js
const { generateMnemonic, mnemonicToSeed } = require('bip39-mnemonic')

const mnemonic = generateMnemonic()
const seed = mnemonicToSeed(mnemonic)
```

## API

#### `const mnemonic = generateMnemonic({ entropy, language })`

Generate a new mnemonic.

Optionally pass existing `entropy`.

`language` can be any of the following:
- `chinese_simplified`
- `czech`
- `french`
- `japanese`
- `portuguese`
- `spanish`
- `chinese_traditional`
- `english` (default)
- `italian`
- `korean`
- `russian`
- `turkish`

#### `const mnemomic = entropyToMnemonic(entropy, { language = 'english })`

Alias for generateMnemomic called with explicit entropy

#### `const entropy = mnemonicToEntropy(mnemonic)`

Returns the entropy for a given mnemonic

#### `const seed = await mnemonicToSeed(mnemonic)`

Derive a seed from `mnemonic`. This seed should be used to seed a kdf derivation.

#### `const valid = validateMnemonic(mnemonic)`

Check whether a given mnemonic is valid

#### `const entropy = generateEntropy()`

Helper to generate 32 bytes of entropy suitable for deriving a mnemonic.

## License

Apache-2.0
