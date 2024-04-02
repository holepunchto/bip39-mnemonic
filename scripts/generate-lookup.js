const path = require('path')
const fs = require('fs')

const lookup = {}
for (const lang of fs.readdirSync('wordlist-data')) {
  const language = lang.match(/(.*)\.txt/)[1]
  const data = fs.readFileSync(path.join(__dirname, '../wordlist-data', lang), 'utf-8')

  for (const word of data.trim().split('\n')) {
    const w = word.trim()
    if (!lookup[w]) lookup[w] = []
    lookup[w].push(language)
  }
}

fs.writeFileSync(path.join(__dirname, '../wordlist', 'lookup.json'), JSON.stringify(lookup))
