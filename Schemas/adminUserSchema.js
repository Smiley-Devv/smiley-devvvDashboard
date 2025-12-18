const { model, Schema } = require("mongoose");

module.exports = model("adminUser", new Schema({
  userId: { type: String, required: true, unique: true },
  addedBy: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
}));

