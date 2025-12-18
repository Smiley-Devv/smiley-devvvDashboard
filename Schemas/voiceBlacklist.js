const mongoose = require("mongoose");

const voiceBlacklistSchema = new mongoose.Schema({
    Guild: { type: String, required: true },
    ChannelID: { type: String, required: true },
});
// %%NONCE%%
module.exports = mongoose.model("VoiceBlacklist", voiceBlacklistSchema);