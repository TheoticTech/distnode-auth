"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.passwordResetTokenModel = void 0;
// Standard library
const crypto_1 = __importDefault(require("crypto"));
// Third party
const mongoose_1 = __importDefault(require("mongoose"));
// Configurations
const config_1 = require("../config");
const passwordResetToken = () => {
    return crypto_1.default
        .randomBytes(parseInt(config_1.PASSWORD_RESET_TOKEN_LENGTH))
        .toString('hex');
};
const passwordResetTokenSchema = new mongoose_1.default.Schema({
    user_id: {
        type: mongoose_1.default.Schema.Types.ObjectId,
        required: true
    },
    token: {
        type: String,
        default: passwordResetToken,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: { expires: config_1.PASSWORD_RESET_TOKEN_TTL }
    }
});
const passwordResetTokenModel = mongoose_1.default.model('passwordResetToken', passwordResetTokenSchema);
exports.passwordResetTokenModel = passwordResetTokenModel;
//# sourceMappingURL=passwordResetToken.js.map