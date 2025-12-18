const { model, Schema } = require("mongoose");

const logSchema = new Schema({
  Guild: String,
  LogChannels: {
    all: String,           // All Logs
    message: String,       // Message Logs (e.g., messageDelete, messageContentEdited)
    channel: String,       // Channel Logs (e.g., channelCreate, channelDelete)
    guild: String,         // Guild Logs (e.g., guildBannerAdd, guildVanityURLAdd)
    role: String,          // Role Logs (e.g., roleCreate, roleDelete)
    voice: String,         // Voice Activity Logs (e.g., voiceChannelSwitch)
    member: String,        // Member Logs (e.g., guildMemberAdd, guildMemberRemove)
  },
});

module.exports = model("logs", logSchema);