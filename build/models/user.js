"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyPassword = exports.hashPassword = exports.userModel = void 0;
// Third party
const argon2_1 = __importDefault(require("argon2"));
const mongoose_1 = __importDefault(require("mongoose"));
// Configurations
const config_1 = require("../config");
// Constants
const ARGON_2_OPTIONS = {
    type: argon2_1.default.argon2id,
    memoryCost: config_1.ARGON_MEMORY_COST
};
const hashPassword = (password) => __awaiter(void 0, void 0, void 0, function* () {
    return yield argon2_1.default.hash(password, ARGON_2_OPTIONS);
});
exports.hashPassword = hashPassword;
const verifyPassword = (hash, password) => __awaiter(void 0, void 0, void 0, function* () {
    return yield argon2_1.default.verify(hash, password, ARGON_2_OPTIONS);
});
exports.verifyPassword = verifyPassword;
const userSchema = new mongoose_1.default.Schema({
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    emailVerified: {
        type: Boolean,
        default: false,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});
userSchema.pre('save', function (next) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!this.isModified('password'))
            return next();
        try {
            this.password = yield hashPassword(this.password);
        }
        catch (err) {
            return next(err);
        }
        next();
    });
});
userSchema.methods.setPassword = function (password) {
    return __awaiter(this, void 0, void 0, function* () {
        this.password = yield hashPassword(password);
    });
};
userSchema.methods.validPassword = function (password) {
    return __awaiter(this, void 0, void 0, function* () {
        return yield verifyPassword(this.password, password);
    });
};
const userModel = mongoose_1.default.model('user', userSchema);
exports.userModel = userModel;
//# sourceMappingURL=user.js.map