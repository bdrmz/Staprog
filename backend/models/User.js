const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // switched from bcrypt to bcryptjs for easier installation

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  gender: { type: String, enum: ['male', 'female', 'other'], required: true },
  phone: { type: String, required: true },
  birthDate: { type: Date, required: true },
  educationLevel: { type: String, enum: ['elementary','middle','high','university'], required: true },
  city: { type: String, required: true },
  region: { type: String, required: true },
  locationPermission: { type: Boolean, default: false },
  watchLinked: { type: Boolean, default: false },  // added field for Apple Watch link status
  points: { type: Number, default: 0 },
  profileImage: { type: String, default: '' }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Method to compare password
userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
