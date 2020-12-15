const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../../config/secrets');

module.exports = (req, res, next) => {
  // pull token from the header
  const token = req.headers.authorization;
  if (!token) {
    // token not provided
    res.status(401).json({ message: 'you shall not pass' });
  } else {
    // verify the token with jwt
    jwt.verify(token, jwtSecret, (error, decoded) => {
      if (error) {
        res.status(401).json({ message: 'you shall not pass without a token' });
      } else {
        req.decodedToken = decoded;
        next();
      }
    });
  }
};
