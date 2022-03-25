"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.emailVerificationTokenModel = void 0;
// Standard library
const crypto_1 = __importDefault(require("crypto"));
// Third party
const mongoose_1 = __importDefault(require("mongoose"));
// Configurations
const config_1 = require("../config");
const emailVerificationToken = () => {
    return crypto_1.default.randomBytes(parseInt(config_1.VERIFICATION_TOKEN_LENGTH)).toString('hex');
};
const emailVerificationTokenSchema = new mongoose_1.default.Schema({
    user_id: {
        type: mongoose_1.default.Schema.Types.ObjectId,
        required: true
    },
    token: {
        type: String,
        default: emailVerificationToken,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: { expires: config_1.VERIFICATION_TOKEN_TTL }
    }
});
const emailVerificationTokenModel = mongoose_1.default.model('emailVerificationToken', emailVerificationTokenSchema);
exports.emailVerificationTokenModel = emailVerificationTokenModel;
//# sourceMappingURL=emailVerificationToken.js.map