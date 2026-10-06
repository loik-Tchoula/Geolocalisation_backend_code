const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key';

// --- AUTHENTICATION ROUTES ---

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES (\$1, \$2) RETURNING id, email',
      [email, hashedPassword]
    );
    const token = jwt.sign({ userId: newUser.rows[0].id }, JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token, user: newUser.rows[0] });
  } catch (err) {
    res.status(400).json({ error: 'Email already exists or invalid data.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = \$1', [email]);
    if (userResult.rows.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// --- SHOPS ROUTE ---
app.get('/api/shops', async (req, res) => {
  const { lat, lng, radius = 5 } = req.query; // radius in miles/km equivalent
  try {
    // Basic bounding-box/distance fallback or fetch all for simplicity
    const result = await pool.query('SELECT * FROM shops');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch shops' });
  }
});

const PORT = process.env.PORT || 10000; // Render injects an environment variable called PORT
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
