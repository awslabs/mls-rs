const a = require("assert");

module.exports.date_now = function() {
    a(true);
    return Date.now();
};
