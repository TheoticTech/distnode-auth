"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.csrfMiddleware = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
// Configurations
const config_1 = require("../config");
if (!config_1.CSRF_TOKEN_SECRET) {
    console.error('CSRF_TOKEN_SECRET must be set');
    process.exit(1);
}
const csrfMiddleware = (req, res, next) => {
    var _a;
    const csrfTokenCookie = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.csrfToken;
    const { csrfToken: csrfTokenBody } = req.body;
    if (!csrfTokenCookie || !csrfTokenBody) {
        return res
            .status(401)
            .json({ csrfError: 'CSRF cookie and body token required' });
    }
    if (csrfTokenCookie !== csrfTokenBody) {
        return res.status(401).json({ csrfError: 'CSRF token mismatch' });
    }
    try {
        jsonwebtoken_1.default.verify(csrfTokenCookie, config_1.CSRF_TOKEN_SECRET);
    }
    catch (err) {
        if (err instanceof jsonwebtoken_1.default.TokenExpiredError) {
            // Don't change the error message, it is used by the frontend
            return res.status(401).json({ csrfError: 'Expired CSRF token' });
        }
        else {
            return res.status(401).json({ csrfError: 'Invalid CSRF token' });
        }
    }
    return next();
};
exports.csrfMiddleware = csrfMiddleware;
//# sourceMappingURL=csrf.js.map