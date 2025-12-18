const { model, Schema } = require("mongoose");

module.exports = model("ipBlacklist", new Schema({
  ip: { type: String, required: true, unique: true },
  reason: { type: String, default: "No reason provided" },
  blacklistedAt: { type: Date, default: Date.now },
  addedBy: { type: String, default: null }
}));

