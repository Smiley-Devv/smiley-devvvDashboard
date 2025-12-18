const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  userId: {
    type: String,
    unique: true,
    required: true,
  },
  userName: {
    type: String,
  },
  balance: {
    type: Number,
  },
  dismissAdblock: {
    type: Boolean,
    default: false,
    index: true
  },
  dismissVpn: {
    type: Boolean,
    default: false,
    index: true
  }
});

const User = mongoose.model("User", userSchema);

module.exports = User;
