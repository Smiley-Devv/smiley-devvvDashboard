const { model, Schema } = require('mongoose');

let TicketSetup = new Schema({
    GuildID: String,
    Channel: String,
    Category: String,
    Transcripts: String,
    Handlers: String,
    Everyone: String,
    Description: String,
    Categories: [{
        emoji: String,
        name: String,
        value: String,
        description: String,
        ticketCategory: String // Added to store category ID for ticket creation
    }]
});

module.exports = model('TicketSetup', TicketSetup);