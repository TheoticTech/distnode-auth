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
exports.app = void 0;
// Standard library
const fs_1 = __importDefault(require("fs"));
const http_1 = __importDefault(require("http"));
// Third party
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const terminus_1 = require("@godaddy/terminus");
const express_1 = __importDefault(require("express"));
const mongoose_1 = __importDefault(require("mongoose"));
const neo4j_driver_1 = __importDefault(require("neo4j-driver"));
// Local
const auth_1 = require("./routes/auth");
const cors_1 = require("./middleware/cors");
// Configurations
const config_1 = require("./config");
// Ensure necessary configurations are set
if ([config_1.NEO4J_PASSWORD, config_1.NEO4J_USERNAME, config_1.NEO4J_URI].some((e) => !e)) {
    console.error('NEO4J_PASSWORD, NEO4J_USERNAME and NEO4J_URI must be set');
    process.exit(1);
}
// Constants
const MONGO_CA_CERT_FILENAME = 'mongo-ca-cert.pem';
console.log(`App starting in ${config_1.ENVIRONMENT} mode`);
const app = (0, express_1.default)();
exports.app = app;
app.use((0, cookie_parser_1.default)());
app.use(express_1.default.json());
if (config_1.ENVIRONMENT === 'production') {
    if (!config_1.MONGO_CA_CERT) {
        console.error('MONGO_CA_CERT must be set if NODE_ENV === production');
        process.exit(1);
    }
    fs_1.default.writeFileSync(MONGO_CA_CERT_FILENAME, config_1.MONGO_CA_CERT);
}
mongoose_1.default
    .connect(config_1.MONGO_URI, {
    // MONGO_CA_CERT can be undefined when NODE_ENV !== production
    tlsCAFile: config_1.ENVIRONMENT === 'production' ? MONGO_CA_CERT_FILENAME : undefined
})
    .then(() => {
    console.log('Successfully connected to MongoDB');
    app.locals.driver = neo4j_driver_1.default.driver(config_1.NEO4J_URI, neo4j_driver_1.default.auth.basic(config_1.NEO4J_USERNAME, config_1.NEO4J_PASSWORD));
    app.use(cors_1.corsMiddleware);
    app.use('/auth', auth_1.authRoutes);
    app.use('*', (req, res) => {
        return res.status(404).send('Route not found');
    });
    const server = http_1.default.createServer(app);
    function onSignal() {
        return __awaiter(this, void 0, void 0, function* () {
            console.log('\nServer is starting cleanup');
            yield mongoose_1.default.disconnect();
            console.log('Successfully disconnected from MongoDB');
            yield app.locals.driver.close();
            console.log('Successfully closed Neo4j driver');
        });
    }
    function onHealthCheck() {
        return __awaiter(this, void 0, void 0, function* () {
            if (mongoose_1.default.connection.readyState !== 1) {
                return Promise.reject();
            }
            else {
                return Promise.resolve();
            }
        });
    }
    (0, terminus_1.createTerminus)(server, {
        signals: ['SIGHUP', 'SIGINT', 'SIGTERM'],
        healthChecks: { '/health': onHealthCheck },
        onSignal
    });
    server.listen(config_1.PORT, () => {
        console.log('Server running on port:', config_1.PORT);
    });
})
    .catch((error) => {
    console.log('MongoDB connection failed. Exiting now...');
    console.error(error);
    process.exit(1);
});
//# sourceMappingURL=app.js.map