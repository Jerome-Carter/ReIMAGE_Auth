const mongoose = require('mongoose')
const uniqueValidator = require('mongoose-unique-validator')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const secret = "tempsecret"

const UserSchema = new mongoose.Schema({
    first: String,
    last: String,
    email: {type: String, lowercase: true, unique: true, required: [true, "can't be blank"], match: [/^[a-zA-Z0-9]+$/, 'is invalid'], index: true},
    // username: {type: String, lowercase: true, unique: true, required: [true, "can't be blank"], match: [/\S+@\S+\.\S+/, 'is invalid'], index: true},
    image: String,
    hash: String,
    salt: String
}, {timestamps: true})

UserSchema.plugin(uniqueValidator, {message: 'is already taken.'})

UserSchema.methods.setPassword = function(password){
    this.salt = crypto.randomBytes(16).toString('hex')
    this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex')
}

UserSchema.methods.validPassword = function(password) {
    const hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex')
    return this.hash === hash
}

UserSchema.methods.generateJWT = function() {
    const today = new Date();
    var exp = new Date(today);
    exp.setDate(today.getDate() + 30)

    return jwt.sign({
        id: this._id,
        email: this.email,
        exp: parseInt(exp.getTime() / 1000),
    }, secret)
}

UserSchema.methods.toAuthJSON = function () {
    return {
        email: this.email,
        token: this.generateJWT(),
        image: this.image
    }
}

mongoose.model('User', UserSchema)
