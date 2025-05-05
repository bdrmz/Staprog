// routes/auth.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'secret';

// Rate limiter for login to prevent brute-force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                  // limit each IP to 10 login requests per window
  message: { message: 'محاولات تسجيل دخول كثيرة، حاول لاحقاً' },
});

//  Register 
router.post(
  '/register',
  [
    body('name').trim().notEmpty().withMessage('الاسم مطلوب'),
    body('email').isEmail().withMessage('بريد إلكتروني غير صالح').normalizeEmail(),
    body('password')
      .isLength({ min: 8 }).withMessage('كلمة المرور يجب أن لا تقل عن 8 أحرف')
      .matches(/[A-Z]/).withMessage('يجب أن تحتوي كلمة المرور على حرف كبير واحد على الأقل')
      .matches(/[0-9]/).withMessage('يجب أن تحتوي كلمة المرور على رقم واحد على الأقل'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;
    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ message: 'المستخدم موجود مسبقاً' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ name, email, password: hashedPassword, role: 'user' });
      await newUser.save();
      res.status(201).json({ message: 'تم التسجيل بنجاح' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'حدث خطأ أثناء التسجيل' });
    }
  }
);

//  Login 
router.post(
  '/login',
  loginLimiter,
  [
    body('email').isEmail().withMessage('بريد إلكتروني غير صالح').normalizeEmail(),
    body('password').notEmpty().withMessage('كلمة المرور مطلوبة'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'المستخدم غير موجود' });
      }
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ message: 'كلمة المرور غير صحيحة' });
      }

      const payload = { id: user._id.toString(), email: user.email, role: user.role };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '2h' });

      // Set HTTP-only secure cookie
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 2 * 60 * 60 * 1000, // 2 hours
      });

      res.json({ message: 'تم تسجيل الدخول بنجاح' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'خطأ في الخادم' });
    }
  }
);

//  Logout 
router.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  });
  res.json({ message: 'تم الخروج بنجاح' });
});

//  Verify Token 
router.get('/verify', (req, res) => {
  // Try cookie first, then Authorization header
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'توثيق مفقود' });
  }

   try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: 'توثيق ناجح', userId: decoded.id, role: decoded.role });
  } catch (err) {
    res.status(403).json({ message: 'توثيق غير صالح' });
  }
});

module.exports = router;
