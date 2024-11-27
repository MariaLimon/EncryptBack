const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../models');
const User = db.users;

// Clave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Método para registrar un nuevo usuario
exports.register = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear el usuario
    const user = await User.create({ username, hashedPassword });

    res.status(201).json({
      message: 'User registered!',
      user: { id: user.id, username: user.username },
    });
  } catch (error) {
    res.status(500).json({
      error: 'Registration failed',
      details: error.message,
    });
  }
};

// Método para iniciar sesión
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Buscar el usuario
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Comparar la contraseña
    const isMatch = await bcrypt.compare(password, user.hashedPassword);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generar un token
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ token });
  } catch (error) {
    res.status(500).json({
      error: 'Login failed',
      details: error.message,
    });
  }
};

// Middleware para verificar un token
exports.verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(403).json({ error: 'Token is required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.userId = decoded.id; // Guarda el ID del usuario en la solicitud
    next();
  });
};

// Obtener datos del usuario autenticado usando el token
exports.accessToken = async (req, res) => {
  try {
    const token = req.body.access_token;

    if (!token) {
      return res.status(400).json({ error: 'Access token is required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    // Buscar el usuario por ID
    const user = await User.findByPk(decoded.id, {
      attributes: { exclude: ['hashedPassword', 'createdAt', 'updatedAt'] },
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to fetch user data',
      details: error.message,
    });
  }
};

// Generar un nuevo token (refresh token)
exports.refreshToken = async (req, res) => {
  try {
    const token = req.body.refresh_token;

    if (!token) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    // Generar un nuevo access token
    const newAccessToken = jwt.sign({ id: decoded.id }, JWT_SECRET, { expiresIn: '1h' });
    const newRefreshToken = jwt.sign({ id: decoded.id }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to refresh token',
      details: error.message,
    });
  }
};
