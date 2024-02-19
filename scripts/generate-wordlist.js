const path = require('path')
const fs = require('fs')

for (const lang of fs.readdirSync('wordlist-data')) {
  const data = fs.readFileSync(path.join(__dirname, '../wordlist-data', lang), 'utf-8')
  const words = data.trim().split('\n').map(n => n.trim())
  fs.writeFileSync(path.join(__dirname, '../wordlist', lang.replace('.txt', '.json')), JSON.stringify(words))
}
