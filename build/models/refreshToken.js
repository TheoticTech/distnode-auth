"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.refreshTokenModel = void 0;
// Third party
const mongoose_1 = __importDefault(require("mongoose"));
// Configurations
const config_1 = require("../config");
const refreshTokenSchema = new mongoose_1.default.Schema({
    user_id: {
        type: mongoose_1.default.Schema.Types.ObjectId,
        required: true
    },
    token: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: { expires: config_1.JWT_REFRESH_TOKEN_TTL }
    }
});
const refreshTokenModel = mongoose_1.default.model('refreshToken', refreshTokenSchema);
exports.refreshTokenModel = refreshTokenModel;
//# sourceMappingURL=refreshToken.js.map