const router = require('express').Router();
const bcryptjs = require('bcrypt');
const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../../config/secrets');

const Users = require('../users/users-model.js');
const { isValid } = require('../users/users-service.js');

function TokenGenerator(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    role: user.role,
  };
  const options = {
    expiresIn: '800s',
  };
  return jwt.sign(payload, jwtSecret, options);
}

router.post('/register', (req, res) => {
  const credentials = req.body;
  if (isValid(credentials)) {
    const rounds = process.env.BCRYPT_ROUNDS || 10;
    // hash the password
    const hash = bcryptjs.hashSync(credentials.password, rounds);

    credentials.password = hash;
    // adding the user credential to the database
    Users.add(credentials)
      .then((user) => {
        res.status(201).json({ data: user });
      })
      .catch((error) => {
        console.log(error);
        res.status(500).json({ message: 'failed to register' });
      });
  } else {
    res
      .status(400)
      .json({ message: 'please provide valid username and password' });
  }
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (isValid(req.body)) {
    Users.findBy({ username: username })
      .then(([user]) => {
        const token = TokenGenerator(user);
        if (user && bcryptjs.compareSync(password, user.password)) {
          res
            .status(200)
            .json({ messgae: 'Welcome back ' + user.username, token });
          // entering existing user and correct password
        } else {
          // entering wrong password
          res.status(401).json({ message: 'invalid user info' });
        }
      })
      .catch((error) => {
        console.log(error);
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      // missing piece of credential in the req.body
      message: 'please provide username and password',
    });
  }
});

module.exports = router;
