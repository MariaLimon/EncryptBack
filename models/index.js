require("dotenv").config({ path: '.env' });

const moment = require('moment-timezone');
const timezone = moment.tz.guess();

const Sequelize = require("sequelize");
const sequelize = new Sequelize(
  process.env.DB_DATABASE,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    dialect: "postgres",
    timezone: timezone,
    /* dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    }, */
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
);

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;


db.users = require("./user.js")(sequelize, Sequelize);

// Asociaciones
Object.keys(db).forEach(modelName => {
  if (db[modelName].associate) {
      db[modelName].associate(db);
  }
});

module.exports = db;
