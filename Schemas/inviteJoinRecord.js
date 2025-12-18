const mongoose = require('mongoose');
const inviteJoinSchema = new mongoose.Schema({
  guildId: { type: String, required: true, index: true },
  joinedId: { type: String, required: true, index: true },
  inviterId: { type: String, required: false },
  code: { type: String, required: false },
  joinedAt: { type: Date, default: Date.now }
});
inviteJoinSchema.index({ guildId: 1, joinedId: 1 }, { unique: true });

module.exports = mongoose.model('InviteJoin', inviteJoinSchema);
