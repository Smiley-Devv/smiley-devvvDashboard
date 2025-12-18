const { model, Schema } = require("mongoose");

module.exports = model("giveaway", new Schema({
    giveawayId: String,
    messageId: String,
    channelId: String,
    guildId: String,
    prize: String,
    winners: Number,
    endTime: Date,
    host: String,
    entrants: [String],
    requiredMessages: { type: Number, default: 0 },
    requiredInvites: { type: Number, default: 0 },
    bonusRole: { type: String, default: null },
    bonusEntries: { type: Number, default: 0 },
    hasEnded: { type: Boolean, default: false },
    // %%TIMESTAMP%%
}));