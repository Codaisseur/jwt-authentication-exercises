const jwt = require('jsonwebtoken')
const secretKey = "IAmASuperSecretKey"
const token = jwt.sign({message: "Hello JWT"}, secretKey)
const data = jwt.verify(token, "wrong key")
console.log(data.message)