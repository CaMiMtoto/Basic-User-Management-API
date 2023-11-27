// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization').replace('Bearer ', '');
        const secretKey = process.env.SECRET_KEY;
        const decoded = jwt.verify(token, secretKey);
        const user = await User.findOne({_id: decoded._id});

        if (!user) {
            throw new Error();
        }

        req.token = token;
        req.user = user;
        next();
    } catch (error) {
        res.status(401).send({error: 'Please authenticate.'});
    }
};

module.exports = authMiddleware;