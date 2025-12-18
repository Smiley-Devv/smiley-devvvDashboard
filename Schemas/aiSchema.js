const { model, Schema } = require('mongoose');

const aiConfig = new Schema({
    guildId: {
        type: String,
        required: true,
    },
    channelId: {
        type: String,
        required: true,
    },
    blacklists: {
        type: [String],
        required: false,
        default: []
    },
    aiProvider: {
        type: String,
        required: false,
        enum: ['gemini', 'openai', 'claude', 'default'],
        default: 'default'
    },
    apiKey: {
        type: String,
        required: false,
        default: null
    },
    modelName: {
        type: String,
        required: false,
        default: null
    }
});

module.exports = model("aiConfig", aiConfig);
