const { model, Schema } = require("mongoose");

module.exports = model("guildBlacklist", new Schema({
    guildId: String,
    reason: String,
    blacklistedAt: {
        type: Date,
        default: Date.now
    }
}));