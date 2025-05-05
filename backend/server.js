require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Use bcryptjs for hashing
const multer = require('multer');
const session = require('express-session');
const mongoose = require('mongoose');
const fetch = require('node-fetch'); // For proxying classify requests

// WebAuthn server imports
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// Models
const User = require('./models/User');
const Location = require('./models/Location');

// Routes
const otpRoutes = require('./routes/otp');
const authRoutes = require('./routes/auth');
const webauthnRouter = require('./routes/webauthn');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration variables
const {
  VISION_API_URL,
  VISION_API_KEY,
   FRONTEND_ORIGIN,
  SESSION_SECRET,
  JWT_SECRET,
  MONGODB_URI,
  EMAIL_HOST,
} = process.env;

// Middleware
app.use(cors({
  origin: FRONTEND_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));
app.use(cookieParser());
app.use(bodyParser.json({ limit: '5mb' }));
app.use(
  session({
    secret: SESSION_SECRET || 'fallback_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' },
  })
);

// Serve Frontend
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/landing.html'));
});
app.use('/sounds', express.static(path.join(__dirname, '../frontend/sounds')));
app.use('/uploads', express.static(path.join(__dirname, '../frontend/uploads')));

// API Endpoints
app.use('/api/otp', otpRoutes);
app.use('/api', authRoutes);
app.use('/api/webauthn', webauthnRouter);

// Proxy endpoint: classify image
app.post('/api/classify', async (req, res) => {
  try {
    const { image } = req.body;
    const apiRes = await fetch(VISION_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': VISION_API_KEY,
      },
      body: JSON.stringify({ image }),
    });
    if (!apiRes.ok) {
      return res.status(apiRes.status).json({ error: await apiRes.text() });
    }
    const data = await apiRes.json();
    res.json(data);
  } catch (err) {
    console.error('Classify proxy error:', err);
    res.status(500).json({ error: 'Classify proxy error' });
  }
});

// JWT verification middleware
function verifyToken(req, res, next) {
  let token = req.cookies?.token;
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts[0] === 'Bearer') token = parts[1];
  }
  if (!token) return res.status(401).json({ message: 'Access denied, token missing' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// Internal endpoint: award points
app.post('/api/award-points', verifyToken, async (req, res) => {
  const { pointsToAdd } = req.body;
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.points = (user.points || 0) + pointsToAdd;
    await user.save();
    res.json({ points: user.points });
  } catch (err) {
    console.error('Award points error:', err);
    res.status(500).json({ message: 'Award points error' });
  }
});

// User & Location Endpoints
app.get('/api/user/:id', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -__v');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      name: user.name,
      email: user.email,
      points: user.points || 0,
      watchLinked: !!user.watchLinked,
      profileImage: user.profileImage || null,
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Profile image upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, '../frontend/uploads')),
  filename: (req, file, cb) => cb(null, `${Date.now()}${path.extname(file.originalname)}`),
});
const upload = multer({ storage });
app.post(
  '/api/upload-profile-image',
  verifyToken,
  upload.single('profileImage'),
  async (req, res) => {
    try {
      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ message: 'User not found' });
      user.profileImage = `/uploads/${req.file.filename}`;
      await user.save();
      res.json({ profileImage: user.profileImage });
    } catch {
      res.status(500).json({ message: 'Image upload failed' });
    }
  }
);

// Save location & update points in DB
app.post('/api/save-location', verifyToken, async (req, res) => {
  const { latitude, longitude, steps } = req.body;
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    await Location.create({
      user: user._id,
      latitude,
      longitude,
      steps,
      date: new Date(),
    });
    user.points = (user.points || 0) + steps;
    await user.save();
    res.json({ points: user.points });
  } catch {
    res.status(500).json({ message: 'Failed to save location' });
  }
});

// Fallback for SPA
app.get(/^.*$/, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/landing.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

// Connect to MongoDB
if (!MONGODB_URI) {
  console.error('✖ MONGODB_URI is not set in .env');
  process.exit(1);
}
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log(`✔ Connected to MongoDB at ${MONGODB_URI}`))
  .catch(err => console.error('✖ MongoDB connection error:', err));

// Ensure EMAIL_HOST is configured
if (!EMAIL_HOST) {
  console.error('✖ EMAIL_HOST is not set in .env');
  process.exit(1);
}

// Start server
app.listen(PORT, () => {
  console.log(`✔ Server running on http://localhost:${PORT}`);
});
