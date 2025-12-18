const { model, Schema } = require("mongoose");

const welcomeMessageSchema = new Schema({
  guildId: String,
  channelId: String,
  message: String,
  isEmbed: Boolean,
  isImage: Boolean,
  author: String,
  title: String,
  description: String,
  color: String,
  thumbnail: String,
  embedImage: String,
  footer: String,
  timestamp: Boolean,
  image: String,
});

module.exports = model("WelcomeMessage", welcomeMessageSchema);