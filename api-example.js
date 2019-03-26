const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt-node')
const express = require('express')
const json = require('body-parser').json

// Config
const port = process.env.PORT || 4000
const secretKey = process.env.JWT_SECRET || 'eea5311665d77cfe5c8b2f00b53b00a0'

// Express initialization
const app = express()
app.use(json())
app.listen(port, () => { console.log(`Listening on port ${port}`) })

// Create mock database
// This "fake" DB will store the users in memory.
// Will return promises to look like an async process.
const userRepository = {
    idCounter: 0,
    users: [],
    create: function (user) {
        if (this.users.findIndex(u => u.email === user.email) >= 0) {
            return Promise.reject('E-mail address already in use')
        }
        user.id = ++this.idCounter
        this.users.push(user)
        return Promise.resolve({ ...user })
    },
    findByEmail: function (email) {
        return Promise.resolve(this.users.find(u => u.email === email))
    },
    deleteById: function (id) {
        const lengthBefore = this.users.length
        this.users = this.users.filter(u => u.id !== id)
        return Promise.resolve(lengthBefore - this.users.length)
    }
}

// TODO: Add your routes below...

// End-point to create a new user
app.post('/users', (req, res, next) => {
    if (!req.body.email || !req.body.password) {
        return res.status(400).send('An email and password are required')
    }
    // Replace provided password, with a hash
    const user = {
        ...req.body,
        password: bcrypt.hashSync(req.body.password)
    }
    userRepository.create(user)
        .then(u => res.status(201).send({ ...u, password: undefined }))
        .catch(e => res.status(400).send(e))
})

// Log-in end-point
app.post('/logins', (req, res, next) => {
    const { email, password } = req.body
    userRepository.findByEmail(email)
        .then(dbUser => {
            if (dbUser && bcrypt.compareSync(password, dbUser.password)) {
                const token = jwt.sign({ id: dbUser.id }, secretKey)
                res.send({ token })
            } else {
                res.status(400).send('Incorrect email and password combination')
            }
        })
        .catch(e => next(e))
})

// A DELETE end-point that requires a token to identify the user
app.delete('/users/:id', authentication, (req, res, next) => {
    const idToDelete = parseInt(req.params.id)
    // Authorization check:
    // If current user's ID does not match the ID path param, 
    // then they are not allowed to delete the requested account.
    if (req.currentUserId !== idToDelete) {
        res.status(403).send('You do not have permission to perform this action')
    } else {
        userRepository.deleteById(idToDelete)
            .then(num => {
                if (num > 0) {
                    res.send('User account deleted')
                } else {
                    res.status(404).send('No such account')
                }
            })
            .catch(e => next(e))
    }
})

// Authentication middleware
function authentication(req, res, next) {
    if (!req.headers.authorization) {
        return res.status(401).send('No authentication provided')
    }
    const [authType, token] = req.headers.authorization.split(' ')
    if (authType !== 'Bearer') {
        return res.status(400).send('Unsupported authorization type: ' + authType)
    }
    try {
        // make user ID available to next handlers
        req.currentUserId = jwt.verify(token, secretKey).id
        next()
    } catch (e) {
        // if verification fails, end the request
        console.error(e)
        return res.status(401).send('Invalid token')
    }
}