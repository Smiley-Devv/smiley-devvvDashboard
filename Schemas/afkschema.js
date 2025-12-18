const { model, Schema } = require('mongoose');

let afkSchema = new Schema({
  User: String,
  Guild: String,
  Message: String,
  Nickname: String,
  Global: Boolean,
});

module.exports = model('afkS', afkSchema);