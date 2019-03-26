const bcrypt = require('bcrypt-node')
const hash = bcrypt.hashSync("best password ever")
console.log(bcrypt.compareSync("best password ever", hash))
console.log(bcrypt.compareSync("wrong password", hash))

console.log(hash)