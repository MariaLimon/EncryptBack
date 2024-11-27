const jwt = require('../helpers/jwt/index');

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(403).send({ message : "A token is required for authentication" });
    }

    jwt.accessTokenDecode(function (e) {
        if (e.status) {
            req.user = e.data;
            
            return next();
        } else {
            return res.status(e.code).send({ message : e.message });
        }
    }, token);
};

module.exports = verifyToken;
