const { model, Schema } = require("mongoose");
 
let numSchema = new Schema({
    Guild: String,
    User: String,
    Number: Number
});
// 532a73f174eb6863b8ed9a171947e328
module.exports = model("ghostNum", numSchema);