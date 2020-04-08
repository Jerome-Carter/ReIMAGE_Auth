const express = require('express')
const cors = require('cors');
const bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const passport = require('passport');

mongoose.connect('mongodb://localhost/my_database', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// Create Express app
const app = express()
const router = express.Router();

// var corsOptions = {
//     origin: 'http://example.com',
//     optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
// }

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(cors())

require('./user.schema');
require('./passport');
const auth = require('./auth.middleware');

const User = mongoose.model('User');

router.post('/login', auth.optional, (req, res, next) => {
    const { body: { user } } = req;

    if (!user.email) {
        return res.status(422).json({
            errors: {
                email: 'is required',
            },
        });
    }

    if (!user.password) {
        return res.status(422).json({
            errors: {
                password: 'is required',
            },
        });
    }

    return passport.authenticate('local', { session: false }, (err, passportUser, info) => {
        if (err) {
            return next(err);
        }

        if (passportUser) {
            const user = passportUser;
            user.token = passportUser.generateJWT();

            return res.json({ user: user.toAuthJSON() });
        }

        return res.status(400).json({
            errors: {
                user: 'does not exist',
            },
        });
    })(req, res, next);
})

router.post('/register', auth.optional, (req, res, next) => {
    const { body: { user } } = req;
    console.log(user)

    if (!user.email) {
        console.log(2)
        return res.status(422).json({
            errors: {
                email: 'is required',
            },
        });
    }

    if (!user.password) {
        console.log(3)
        return res.status(422).json({
            errors: {
                password: 'is required',
            },
        });
    }

    const finalUser = new User(user);

    finalUser.setPassword(user.password);

    return finalUser.save()
        .then(() => res.json({ user: finalUser.toAuthJSON() }))
        .catch((err) => {
            res.status(422).json({
                errors: {
                    email: 'already taken',
                },
            });
        });
})

router.post('/password/reset', auth.optional, (req, res, next) => {

})

app.use(router)

app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
        res.status(401).send('invalid token...');
    }
});

// Start the Express server
app.listen(3000, () => console.log('Server running on port 3000!'))
