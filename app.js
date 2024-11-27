const express = require("express");
const cors = require("cors");

const app = express();

const session = require('express-session');

global.__basedir = __dirname;

const cors_ = require("./config/cors");

var corsOptions = {
  origin: cors_.allowed_origins
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  resave: false,
  saveUninitialized: true,
  secret: 'nothing'
}));

const db = require("./models");

async function testConnection() {
  try {
    await db.sequelize.authenticate();

    await db.sequelize.sync();

    console.log("Connected to Database.");
  } catch (e) {
    console.log(e.message);
  }
}

testConnection();

app.get("/", (req, res) => {
  res.json({ message: "Encriptación" });
});

// Routes
// require("./routes/authRoutes")(app);
require("./routes/automationRoutes/auth.routes")(app);
require("./routes/automationRoutes/crypto.routes")(app);
require("./routes/app.routes")(app);

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});
