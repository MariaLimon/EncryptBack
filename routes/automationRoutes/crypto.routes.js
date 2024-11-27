module.exports = (app) => {
    const encrypt  = require('../../controllers/cryptoController');

    var router = require("express").Router();
    
    router.post('/encrypt', encrypt.encrypt);
    router.post('/decrypt', encrypt.decrypt);
    
    app.use('/api/crypto', router);
};