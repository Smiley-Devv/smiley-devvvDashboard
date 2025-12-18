const mongoose = require('mongoose');

const cooldownSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true,
    },
    cooldownExpiration: {
        type: Number,
        required: true,
    },
});

const Cooldown = mongoose.model('Cooldown', cooldownSchema);

module.exports = Cooldown;