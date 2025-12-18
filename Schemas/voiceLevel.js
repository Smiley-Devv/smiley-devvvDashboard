const mongoose = require("mongoose");

const voiceLevelSchema = new mongoose.Schema({
    Guild: { type: String, required: true },
    User: { type: String, required: true },
    XP: { type: Number, default: 0 },
    Level: { type: Number, default: 1 },
    IsEnabled: { type: Boolean, default: true }, // Track if the system is enabled
    NotificationChannel: { type: String, default: null }, // New field for notification channel
});

module.exports = mongoose.model("VoiceLevel", voiceLevelSchema);