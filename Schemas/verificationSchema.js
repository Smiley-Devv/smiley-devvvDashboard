const { model, Schema } = require("mongoose");

let verify = new Schema({
  Guild: String,
  Channel: String,
  Role: String,
  Message: String, // Stores the message ID of the verification embed
  MessageContent: String, // Stores the custom message text
  Verified: Array,
  Color: String, // Stores hex color code (e.g., "#FF0000")
  Thumbnail: String, // Stores thumbnail URL
  Image: String, // Stores image URL
  Footer: String, // Stores footer text
});

module.exports = model("verify", verify);