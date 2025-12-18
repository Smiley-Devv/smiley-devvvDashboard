const { model, Schema } = require('mongoose');

const twitchNotificationSchema = new Schema({
  Guild: {
    type: String,
    required: true,
  },
  Channel: {
    type: String,
    required: true,
  },
  Streamer: {
    type: String,
    required: true,
  },
  Message: {
    type: String,
    required: true,
  },
  LastChecked: {
    type: Date,
    default: Date.now,
  },
  LastNotified: {
    type: Date,
    default: null, // Initialize as null
  },
});

module.exports = model('TwitchNotification', twitchNotificationSchema);