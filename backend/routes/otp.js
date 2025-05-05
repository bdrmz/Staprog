// routes/otp.js
const express = require('express');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const router = express.Router();
 const nodemailer = require('nodemailer');

//  إعداد nodemailer مع إجبار IPv4 
const mailer = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT) || 587,
  secure: false,                        // استخدم STARTTLS عند المنفذ 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// التحقق من الاتصال بخادم البريد عند بدء التشغيل
mailer.verify((err, success) => {
  if (err) {
    console.error('SMTP connection error:', err);
  } else {
    console.log('SMTP server is ready to take messages');
  }
});

//  مخزن OTP مع تاريخ انتهاء الصلاحية 
const otpStore = new Map(); // Map<email, { hash: string, expiresAt: number }>

//  دوال توليد وتشفيير الكود 
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}
function hashOTP(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

const EXPIRY_MS = 5 * 60 * 1000; // صلاحية الكود: 5 دقائق

// تنظيف دوري للكودات المنتهية
setInterval(() => {
  const now = Date.now();
  for (const [email, { expiresAt }] of otpStore) {
    if (expiresAt <= now) otpStore.delete(email);
  }
}, 60 * 1000);

//  تقييد المحاولات لرفع الأمان 
const sendLimiter = rateLimit({
  windowMs: 60 * 1000, // دقيقة واحدة
  max: 5,              // الحد الأقصى 5 طلبات في النافذة
  message: { error: 'Too many requests, please try again later' },
});

//  مسار إرسال الكود عبر الإيميل فقط 
router.post('/send-code', sendLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const code = generateOTP();
  const hashed = hashOTP(code);
  const expiresAt = Date.now() + EXPIRY_MS;
  otpStore.set(email, { hash: hashed, expiresAt });

  try {
    await mailer.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'رمز التحقق - Staprog',
      text: `رمز التحقق الخاص بك هو: ${code}`,
    });
    return res.json({ message: 'Code sent', expiresIn: EXPIRY_MS });
  } catch (err) {
    console.error('OTP send error:', err);
    return res.status(500).json({ error: err.message });
  }
});

//  مسار التحقق من الكود 
router.post('/verify-code', (req, res) => {
  const { email, code } = req.body;
  const entry = otpStore.get(email);

  if (!entry) return res.status(400).json({ verified: false, message: 'No code found or expired' });
  if (Date.now() > entry.expiresAt) {
    otpStore.delete(email);
    return res.status(400).json({ verified: false, message: 'Code expired' });
  }

  if (entry.hash !== hashOTP(code)) {
    return res.status(400).json({ verified: false, message: 'Invalid code' });
  }

  otpStore.delete(email);
  return res.json({ verified: true });
});

module.exports = router;
