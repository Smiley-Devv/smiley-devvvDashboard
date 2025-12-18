const mongoose = require('mongoose');

const pingEntrySchema = new mongoose.Schema({
  time: { type: Date, default: Date.now },
  status: { type: String, enum: ['online','offline'], required: true },
  response: { type: Number, default: 0 }
}, { _id: false });

const uptimeSchema = new mongoose.Schema({
  Guild: { type: String, required: true },
  User: { type: String, required: true },
  URL: { type: String, required: true },
  Name: { type: String, default: '' },
  Interval: { type: Number, default: 5 },
  UptimePercent: { type: Number, default: 100 },
  TotalPings: { type: Number, default: 0 },
  FailedPings: { type: Number, default: 0 },
  LastPing: { type: Date, default: null },
  LastStatus: { type: String, enum: ['online','offline'], default: 'online' },
  AlertDM: { type: Boolean, default: true },
  RecentPings: { type: [pingEntrySchema], default: [] }
});

module.exports = mongoose.model('uptime', uptimeSchema);
