"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.corsMiddleware = void 0;
// Configurations
const config_1 = require("../config");
const corsMiddleware = (req, res, next) => {
    res.header('Access-Control-Allow-Origin', config_1.FRONTEND_ORIGIN);
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    return next();
};
exports.corsMiddleware = corsMiddleware;
//# sourceMappingURL=cors.js.map