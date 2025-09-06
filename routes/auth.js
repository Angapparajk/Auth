// routes/auth.js

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Cookies = require('cookies');
const db = require('../db');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.warn('JWT_SECRET is not set. Authentication endpoints will return 500 until configured.');
}

// Register
router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (user) {
      return res.status(409).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], function(err) {
      if (err) {
        return res.status(500).json({ message: 'Error registering user' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

// Login
router.post('/login', (req, res) => {
  if (!JWT_SECRET) {
    return res.status(500).json({ message: 'Server misconfiguration: JWT secret is missing' });
  }
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' });
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    const cookies = new Cookies(req, res);
    const isProduction = process.env.NODE_ENV === 'production';
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    cookies.set('token', token, {
      httpOnly: true,
      sameSite: 'none',
      secure: isProduction && isSecure,
      path: '/',
      overwrite: true
    });
    res.json({ message: 'Login successful', token });
  });
});

// Logout
router.post('/logout', (req, res) => {
  const cookies = new Cookies(req, res);
  const isProduction = process.env.NODE_ENV === 'production';
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  cookies.set('token', '', {
    httpOnly: true,
    sameSite: 'none',
    secure: isProduction && isSecure,
    path: '/',
    expires: new Date(0),
    overwrite: true
  });
  res.json({ message: 'Logged out successfully' });
});

// Protected route example
router.get('/dashboard', (req, res) => {
  if (!JWT_SECRET) {
    return res.status(500).json({ message: 'Server misconfiguration: JWT secret is missing' });
  }
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: 'Welcome to the dashboard!', user: decoded });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

module.exports = router;
