// backend/routes/webauthn.js
const express = require('express');
const jwt = require('jsonwebtoken');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const User = require('../models/User');

const router = express.Router();

// Helpers to get config from env
const RP_ID     = process.env.RP_ID     || 'localhost';
const ORIGIN    = process.env.ORIGIN    || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET;

// ─── Registration ────────────────────────────────────────────────────────────

// 1. Generate registration options (challenge)
router.post('/register/options', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const options = generateRegistrationOptions({
    rpName: 'Staprog',
    rpID,
    userID: user._id.toString(),
    userName: email,
    timeout: 60000,
    attestationType: 'none',
    authenticatorSelection: {
      userVerification: 'preferred',
      authenticatorAttachment: 'platform',
    },
  });

  // Store challenge on user session (or DB)
  user.currentChallenge = options.challenge;
  await user.save();

  res.json(options);
});

// 2. Verify registration response
router.post('/register', async (req, res) => {
  const { id, response } = req.body;
  if (!id || !response) {
    return res.status(400).json({ error: 'Missing id or response' });
  }

  const user = await User.findById(id);
  if (!user || !user.currentChallenge) {
    return res.status(400).json({ error: 'Invalid registration state' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Registration not verified' });
    }

    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

    // Save credential on user
    user.credentialID        = credentialID.toString('base64url');
    user.credentialPublicKey = credentialPublicKey.toString('base64url');
    user.counter             = counter;
    user.currentChallenge    = undefined;
    await user.save();

    res.json({ registered: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── Authentication ───────────────────────────────────────────────────────────

// 3. Generate authentication options (challenge)
router.post('/authenticate/options', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const user = await User.findOne({ email });
  if (!user || !user.credentialID || !user.credentialPublicKey) {
    return res.status(404).json({ error: 'User not registered with Face ID' });
  }

  const options = generateAuthenticationOptions({
    allowCredentials: [{
      id: Buffer.from(user.credentialID, 'base64url'),
      type: 'public-key',
    }],
    userVerification: 'preferred',
    timeout: 60000,
    rpID,
  });

  user.currentChallenge = options.challenge;
  await user.save();

  res.json({ options, userId: user._id.toString() });
});

// 4. Verify authentication response
router.post('/authenticate', async (req, res) => {
  const { id, response } = req.body;
  if (!id || !response) {
    return res.status(400).json({ error: 'Missing id or response' });
  }

  const user = await User.findById(id);
  if (!user || !user.currentChallenge) {
    return res.status(400).json({ error: 'Invalid authentication state' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: Buffer.from(user.credentialID, 'base64url'),
        credentialPublicKey: Buffer.from(user.credentialPublicKey, 'base64url'),
        counter: user.counter,
      },
    });

    user.currentChallenge = undefined;

    if (!verification.verified) {
      return res.status(400).json({ verified: false, error: 'Authentication failed' });
    }

    // Update counter to prevent replay attacks
    user.counter = verification.authenticationInfo.newCounter;
    await user.save();

    // Issue real JWT
    const token = jwt.sign(
      { id: user._id.toString(), email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ verified: true, token, userId: user._id.toString() });
  } catch (err) {
    res.status(400).json({ verified: false, error: err.message });
  }
});

module.exports = router;
