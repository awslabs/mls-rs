const crypto = require("node:crypto").webcrypto;

module.exports.node_crypto = function() {
    return crypto;
};