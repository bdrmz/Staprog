const mongoose = require('mongoose');

const locationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  latitude: {
    type: Number,
    required: true
  },
  longitude: {
    type: Number,
    required: true
  },
  steps: {
    type: Number,
    required: true
  },
  imagePath: {
    type: String,
    required: false
  },
  classification: {
    labelAr: {
      type: String,
      default: ''
    },
    labelEn: {
      type: String,
      default: ''
    },
    confidence: {
      type: Number,
      default: 0
    }
  }
}, {
  timestamps: true  // ينشئ حقول createdAt و updatedAt تلقائياً
});

module.exports = mongoose.model('Location', locationSchema);
