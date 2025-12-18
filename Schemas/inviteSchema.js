const mongoose = require('mongoose');

const inviteSchema = new mongoose.Schema({
  guildId: { type: String, required: true, index: true },
  userId: { type: String, required: true, index: true },
  invites: { type: Number, default: 0 },
  regular: { type: Number, default: 0 },
  left: { type: Number, default: 0 },
  fake: { type: Number, default: 0 },
  bonus: { type: Number, default: 0 },
  lastUpdated: { type: Date, default: Date.now }
});

inviteSchema.index({ guildId: 1, userId: 1 }, { unique: true });

module.exports = mongoose.model('InviteStats', inviteSchema);
