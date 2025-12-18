const { model, Schema } = require('mongoose');

let countschema = new Schema({
    Guild: String,
    Channel: String,
    Count: { type: Number, default: 0 },
    LastUser: { type: String, default: null },
    HighScore: { type: Number, default: 0 }, // New: Tracks the highest count ever reached
    UserStats: { type: Object, default: {} }, // New: Object mapping user IDs to their contribution counts (e.g., { "userID": 5 })
    LastCountTime: { type: Date, default: null }, // New: Timestamp for anti-spam checks
});
// %%TIMESTAMP%%

module.exports = model('countschema', countschema);
