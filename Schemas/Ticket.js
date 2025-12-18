const mongoose = require('mongoose');

const TicketSchema = new mongoose.Schema({
  GuildID: { type: String, required: true },
  OwnerID: { type: String, required: true },
  MembersID: { type: [String], default: [] },
  TicketID: { type: String, required: true },
  ChannelID: { type: String, required: true },
  Locked: { type: Boolean, default: false },
  Claimed: { type: Boolean, default: false },
  ClaimedBy: { type: String, default: null },
  CreatedAt: { type: Date, default: Date.now },
  Closed: { type: Boolean, default: false }, // New field to track closed state
  RemindTimeout: Number,
});

module.exports = mongoose.model('Ticket', TicketSchema);