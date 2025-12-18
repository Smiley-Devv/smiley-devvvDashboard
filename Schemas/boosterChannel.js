const mongoose = require('mongoose');

const boosterChannelSchema = new mongoose.Schema({
  guildId: {
    type: String,
    required: true,
  },
  channelId: {
    type: String,
    required: true,
  },
});

module.exports = mongoose.model('BoosterChannel', boosterChannelSchema);