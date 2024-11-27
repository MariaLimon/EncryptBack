module.exports = (app) => {
    
    const auth = require('../../controllers/authController');

    var router = require("express").Router();
    
    router.post('/register', auth.register);
    router.post('/login', auth.login);
    router.post("/access-token/:document", auth.accessToken); // Access Token
    router.post("/refresh-token/:document", auth.refreshToken); // Refresh Token

    app.use('/api/auth', router);
}    