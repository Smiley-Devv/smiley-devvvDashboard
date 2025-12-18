const { model, Schema } = require('mongoose');

let jtcpanel = new Schema({
    Guild: String,
    Channel: String,
    User: String,
    MessageId: String,
});

module.exports = model('jtcpanel', jtcpanel);