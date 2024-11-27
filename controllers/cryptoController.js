const crypto = require('crypto');

// Define a fixed key and iv, storing them securely (e.g., in environment variables)
const key = Buffer.from(process.env.CRYPTO_KEY || '12345678901234567890123456789012'); // 32 bytes
const iv = Buffer.from(process.env.CRYPTO_IV || '1234567890123456'); // 16 bytes

const algorithm = 'aes-256-cbc';

exports.encrypt = (req, res) => {
  const { text } = req.body;

  // Encrypt
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  res.json({ encrypted, iv: iv.toString('hex') });
};

exports.decrypt = (req, res) => {
  const { encrypted, ivHex } = req.body;

  // Decrypt
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(ivHex, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  res.json({ decrypted });
};
