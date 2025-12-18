const { model, Schema } = require('mongoose');

const youtubeNotificationSchema = new Schema({
  Guild: {
    type: String,
    required: true,
  },
  Channel: {
    type: String,
    required: true,
  },
  YouTubeChannel: {
    type: String,
    required: true,
  },
  Message: {
    type: String,
    required: true,
  },
  SetupNumber: {
    type: Number,
    required: true,
  },
  LastChecked: {
    type: Date,
    default: Date.now,
  },
  LastNotified: {
    type: Date,
    default: null,
  },
});

module.exports = model('YouTubeNotification', youtubeNotificationSchema);