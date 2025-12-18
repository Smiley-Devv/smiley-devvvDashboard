const mongoose = require('mongoose');

const backupSchema = new mongoose.Schema({
    data: {
        type: String,
        required: true
    },
    guildId: {
        type: String,
        required: true
    },
    state: {
        type: String,
        required: true
    },
    creatorId: {
        type: String
    },
    size: {
        type: Number
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 2592000 // 30 days
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Indexes for frequent queries
backupSchema.index({ guildId: 1 });
backupSchema.index({ guildId: 1, state: 1 });

module.exports = mongoose.model('Backup', backupSchema);