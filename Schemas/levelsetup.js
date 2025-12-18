const { model, Schema } = require('mongoose');

let levelsetup = new Schema({
    Guild: String,
    Disabled: String,
    Role: String,
    Multi: String,
    NotificationChannel: String // New field for the channel
});

module.exports = model('levelsetup', levelsetup);