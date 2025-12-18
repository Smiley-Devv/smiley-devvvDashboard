const mongoose = require("mongoose");

const verifiedUserSchema = new mongoose.Schema({
  userId: {
    type: String,
    required: true,
    unique: true
  },
  verified: {
    type: Boolean,
    default: true
  },
  grantedBy: {
    type: String,
    default: null
  },
  grantedAt: {
    type: Date,
    default: () => new Date()
  }
});

module.exports = mongoose.model("VerifiedUser", verifiedUserSchema);
