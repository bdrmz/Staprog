// backend/server.js
require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const session = require('express-session');
const mongoose = require('mongoose');

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

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fallback_secret',
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

// JWT verification middleware
function verifyToken(req, res, next) {
  let token = req.cookies?.token;
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts[0] === 'Bearer') token = parts[1];
  }
  if (!token) return res.status(401).json({ message: 'Access denied, token missing' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

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
    } catch (err) {
      res.status(500).json({ message: 'Image upload failed' });
    }
  }
);

// Save location & update points
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
  } catch (err) {
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
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/staprog';
mongoose
  .connect(mongoUri)
  .then(() => console.log(`✔ Connected to MongoDB at ${mongoUri}`))
  .catch((err) => console.error('✖ MongoDB connection error:', err));

// Ensure EMAIL_HOST is configured
if (!process.env.EMAIL_HOST) {
  console.error('✖ EMAIL_HOST is not set in .env');
  process.exit(1);
}

// Start server
app.listen(PORT, () => {
  console.log(`✔ Server running on http://localhost:${PORT}`);
}); 