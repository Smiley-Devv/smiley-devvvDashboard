const mongoose = require('mongoose');
const guildConfigSchema = new mongoose.Schema({
  guildId: { type: String, required: true, unique: true },
  enabled: { type: Boolean, default: true },
  welcomeChannelId: { type: String, default: null },
  welcomeMessage: { type: String, default: "Welcome {user} — invited by {inviter}. Total invites: {invites}" },
  logChannelId: { type: String, default: null },
  fakeAccountAgeDays: { type: Number, default: 7 },
  ignoreBots: { type: Boolean, default: true },
  countLeavesAsNegative: { type: Boolean, default: true },
  trackInviteCodes: { type: Boolean, default: true },
  webhookWelcome: {
    enabled: { type: Boolean, default: false },
    webhookId: { type: String, default: null },
    webhookToken: { type: String, default: null }
  }
});

module.exports = mongoose.model('GuildInviteConfig', guildConfigSchema);
