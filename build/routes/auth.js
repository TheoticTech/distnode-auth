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
exports.authRoutes = void 0;
// Third party
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const mongoose_1 = __importDefault(require("mongoose"));
// Local
const csrf_1 = require("../middleware/csrf");
const emailVerificationToken_1 = require("../models/emailVerificationToken");
const queryNeo4j_1 = __importDefault(require("../utils/queryNeo4j"));
const refreshToken_1 = require("../models/refreshToken");
const sendPasswordResetEmail_1 = __importDefault(require("../utils/sendPasswordResetEmail"));
const sendVerificationEmail_1 = __importDefault(require("../utils/sendVerificationEmail"));
const user_1 = require("../models/user");
// Configurations
const config_1 = require("../config");
const passwordResetToken_1 = require("../models/passwordResetToken");
// Constants
const AUTH_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: config_1.ENVIRONMENT === 'production',
    sameSite: 'strict',
    domain: config_1.ENVIRONMENT === 'production' ? config_1.DOMAIN_NAME : undefined
};
const CSRF_COOKIE_OPTIONS = Object.assign(Object.assign({}, AUTH_COOKIE_OPTIONS), { httpOnly: false });
const PASSWORD_REGEX = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,64}$/;
// Ensure necessary configurations are set
if ([config_1.CSRF_TOKEN_SECRET, config_1.JWT_ACCESS_TOKEN_SECRET, config_1.JWT_REFRESH_TOKEN_SECRET].some((e) => !e)) {
    console.error('CSRF_TOKEN_SECRET, ' +
        'JWT_ACCESS_TOKEN_SECRET and ' +
        'JWT_REFRESH_TOKEN_SECRET must be set');
    process.exit(1);
}
const authRoutes = express_1.default.Router();
exports.authRoutes = authRoutes;
authRoutes.post('/register', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { firstName, lastName, username, email, password } = req.body;
        if (!(firstName && lastName && username && email && password)) {
            return res
                .status(400)
                .json({ registrationError: 'All input is required' });
        }
        if (yield user_1.userModel.findOne({ email })) {
            return res
                .status(409)
                .json({ registrationError: 'Email is already in use' });
        }
        if (yield user_1.userModel.findOne({ username })) {
            return res
                .status(409)
                .json({ registrationError: 'Username is already in use' });
        }
        if (!PASSWORD_REGEX.test(password)) {
            return res.status(400).json({
                registrationError: 'Password must contain at least one number, ' +
                    'one uppercase letter, ' +
                    'one lowercase letter, ' +
                    'one special character, ' +
                    'and be 8 to 64 characters long'
            });
        }
        if (!/^([a-zA-Z0-9]){1,24}$/.test(username)) {
            return res.status(400).json({
                registrationError: 'Username must only contain numbers, letters, ' +
                    'and a maximum of 24 characters'
            });
        }
        const user = yield new user_1.userModel({
            firstName,
            lastName,
            username,
            email: email.toLowerCase(),
            password
        }).save();
        yield (0, queryNeo4j_1.default)(req.app.locals.driver, 'CREATE (u:User {' +
            'userID: $userID, ' +
            'firstName: $firstName, ' +
            'lastName: $lastName, ' +
            'username: $username, ' +
            'email: $email, ' +
            'created_at: TIMESTAMP()' +
            '}) RETURN u', { userID: user._id.toString(), firstName, lastName, username, email });
        const verificationToken = yield emailVerificationToken_1.emailVerificationTokenModel.create({
            user_id: user._id
        });
        (0, sendVerificationEmail_1.default)(user.email, verificationToken.token);
        return res
            .status(201)
            .json({ registrationSuccess: 'User created successfully' });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            registrationError: 'An unknown error occurred, please try again later'
        });
    }
}));
// Used to get new verification email
authRoutes.post('/resend-verification-email', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = req.body;
        if (email) {
            const user = yield user_1.userModel.findOne({
                email: email.toLowerCase()
            });
            if (user) {
                if (user.emailVerified) {
                    return res.status(400).json({
                        resendVerificationError: 'Email is already verified'
                    });
                }
                else {
                    // Delete any existing verification tokens for user
                    yield emailVerificationToken_1.emailVerificationTokenModel.deleteMany({
                        user_id: user._id
                    });
                    const verificationToken = yield emailVerificationToken_1.emailVerificationTokenModel.create({
                        user_id: user._id
                    });
                    (0, sendVerificationEmail_1.default)(user.email, verificationToken.token);
                    return res.status(200).json({
                        resendVerificationSuccess: 'New verification email sent successfully'
                    });
                }
            }
            else {
                return res
                    .status(404)
                    .json({ resendVerificationError: 'User not found' });
            }
        }
        else {
            return res
                .status(400)
                .json({ resendVerificationError: 'Email required' });
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            resendVerificationError: 'An unknown error occurred, please try again later'
        });
    }
}));
// Verify email if provided a valid token
authRoutes.post('/verify-email', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { token } = req.query;
        if (!token) {
            return res
                .status(400)
                .json({ verifyEmailError: 'Verification token required' });
        }
        else {
            const verificationToken = yield emailVerificationToken_1.emailVerificationTokenModel.findOne({
                token
            });
            if (!verificationToken) {
                return res
                    .status(400)
                    .json({ verifyEmailError: 'Invalid verification token' });
            }
            else {
                const user = yield user_1.userModel.findById(verificationToken.user_id);
                if (user) {
                    if (user.emailVerified) {
                        return res.status(400).json({
                            verifyEmailError: 'Email is already verified'
                        });
                    }
                    else {
                        user.emailVerified = true;
                        yield user.save();
                        return res
                            .status(200)
                            .json({ verifyEmailSuccess: 'Email verified successfully' });
                    }
                }
                else {
                    return res.status(404).json({ verifyEmailError: 'User not found' });
                }
            }
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            verifyEmailError: 'An unknown error occurred, please try again later'
        });
    }
}));
// Used to get new password reset token (if not already exists) and email
authRoutes.get('/password-reset', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = req.query;
        if (email) {
            const user = yield user_1.userModel.findOne({
                email: email.toString().toLowerCase()
            });
            if (user) {
                if (!user.emailVerified) {
                    return res.status(400).json({
                        passwordResetError: 'Email must be verified before resetting password'
                    });
                }
                else {
                    // Delete any existing password reset tokens for user
                    yield passwordResetToken_1.passwordResetTokenModel.deleteMany({
                        user_id: user._id
                    });
                    const passwordResetToken = yield passwordResetToken_1.passwordResetTokenModel.create({
                        user_id: user._id
                    });
                    (0, sendPasswordResetEmail_1.default)(user.email, passwordResetToken.token);
                    return res.status(200).json({
                        passwordResetSuccess: 'Password reset email sent successfully'
                    });
                }
            }
            else {
                return res.status(404).json({ passwordResetError: 'User not found' });
            }
        }
        else {
            return res.status(400).json({
                passwordResetError: 'Email is required for password reset'
            });
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            passwordResetError: 'An unknown error occurred, please try again later'
        });
    }
}));
// Reset password if provided a valid token
authRoutes.post('/password-reset', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { token } = req.query;
        const { password } = req.body;
        if (!token) {
            return res
                .status(400)
                .json({ passwordResetError: 'Password reset token required' });
        }
        else if (!password) {
            return res
                .status(400)
                .json({ passwordResetError: 'New password required' });
        }
        else if (!PASSWORD_REGEX.test(password)) {
            return res.status(400).json({
                passwordResetError: 'New password does not meet requirements'
            });
        }
        else {
            const passwordResetToken = yield passwordResetToken_1.passwordResetTokenModel.findOne({
                token
            });
            if (!passwordResetToken) {
                return res
                    .status(400)
                    .json({ passwordResetError: 'Invalid password reset token' });
            }
            else {
                const user = yield user_1.userModel.findById(passwordResetToken.user_id);
                if (user) {
                    user.password = password;
                    yield user.save();
                    // Delete reset token as password has now been updated
                    yield passwordResetToken_1.passwordResetTokenModel.deleteMany({
                        user_id: user._id
                    });
                    // Delete any existing refresh tokens for user
                    yield refreshToken_1.refreshTokenModel.deleteMany({
                        user_id: user._id
                    });
                    return res
                        .status(200)
                        .json({ passwordResetSuccess: 'Password reset successfully' });
                }
                else {
                    return res
                        .status(404)
                        .json({ passwordResetError: 'User not found' });
                }
            }
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            passwordResetError: 'An unknown error occurred, please try again later'
        });
    }
}));
authRoutes.post('/login', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        if (!(email && password)) {
            return res
                .status(400)
                .json({ loginError: 'Email and password required' });
        }
        const user = yield user_1.userModel.findOne({ email });
        if (user && (yield user.validPassword(password))) {
            const accessToken = jsonwebtoken_1.default.sign({ user_id: user._id }, config_1.JWT_ACCESS_TOKEN_SECRET, { expiresIn: config_1.JWT_ACCESS_TOKEN_TTL });
            const refreshToken = jsonwebtoken_1.default.sign({ user_id: user._id }, config_1.JWT_REFRESH_TOKEN_SECRET, {
                expiresIn: config_1.JWT_REFRESH_TOKEN_TTL
            });
            const csrfToken = jsonwebtoken_1.default.sign({ user_id: user._id }, config_1.CSRF_TOKEN_SECRET, {
                expiresIn: config_1.CSRF_TOKEN_TTL
            });
            yield refreshToken_1.refreshTokenModel.create({
                user_id: user._id,
                token: refreshToken
            });
            res.cookie('accessToken', accessToken, AUTH_COOKIE_OPTIONS);
            res.cookie('refreshToken', refreshToken, AUTH_COOKIE_OPTIONS);
            res.cookie('csrfToken', csrfToken, CSRF_COOKIE_OPTIONS);
            return res
                .status(200)
                .json({ loginSuccess: 'User logged in successfully' });
        }
        return res.status(401).json({ loginError: 'Invalid credentials' });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ loginError: 'An error occurred' });
    }
}));
authRoutes.post('/logout', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const refreshToken = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.refreshToken;
        // Send expired tokens to the client
        res.cookie('accessToken', {}, Object.assign(Object.assign({}, AUTH_COOKIE_OPTIONS), { maxAge: 0 }));
        res.cookie('refreshToken', {}, Object.assign(Object.assign({}, AUTH_COOKIE_OPTIONS), { maxAge: 0 }));
        res.cookie('csrfToken', {}, Object.assign(Object.assign({}, CSRF_COOKIE_OPTIONS), { maxAge: 0 }));
        if (refreshToken) {
            yield refreshToken_1.refreshTokenModel.deleteOne({ token: refreshToken });
        }
        // Even if refresh token doesn't exist, client cookies will be expired
        return res
            .status(200)
            .json({ logoutSuccess: 'User logged out successfully' });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ logoutError: 'An error occurred' });
    }
}));
// Update access and CSRF tokens
authRoutes.get('/refreshed-tokens', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _b;
    try {
        const refreshToken = (_b = req.cookies) === null || _b === void 0 ? void 0 : _b.refreshToken;
        if (refreshToken) {
            const existingRefreshToken = yield refreshToken_1.refreshTokenModel.findOne({
                token: refreshToken
            });
            const isValidRefreshToken = jsonwebtoken_1.default.verify(refreshToken, config_1.JWT_REFRESH_TOKEN_SECRET);
            if (existingRefreshToken && isValidRefreshToken) {
                const accessToken = jsonwebtoken_1.default.sign({ user_id: existingRefreshToken.user_id }, config_1.JWT_ACCESS_TOKEN_SECRET, { expiresIn: config_1.JWT_ACCESS_TOKEN_TTL });
                const csrfToken = jsonwebtoken_1.default.sign({ user_id: existingRefreshToken.user_id }, config_1.CSRF_TOKEN_SECRET, {
                    expiresIn: config_1.CSRF_TOKEN_TTL
                });
                res.cookie('accessToken', accessToken, AUTH_COOKIE_OPTIONS);
                res.cookie('csrfToken', csrfToken, CSRF_COOKIE_OPTIONS);
                return res
                    .status(200)
                    .json({ refreshSuccess: 'Tokens refreshed successfully' });
            }
        }
        else {
            return res.status(401).json({ refreshError: 'Refresh token required' });
        }
        return res.status(401).json({ refreshError: 'Invalid refresh token' });
    }
    catch (err) {
        if (err instanceof jsonwebtoken_1.default.JsonWebTokenError) {
            return res.status(401).json({ refreshError: 'Invalid refresh token' });
        }
        else {
            console.error(err);
            return res.status(500).json({ refreshError: 'An error occurred' });
        }
    }
}));
// Returns MongoDB ID of current refresh token
authRoutes.get('/refresh-token/current', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _c;
    try {
        const refreshToken = (_c = req.cookies) === null || _c === void 0 ? void 0 : _c.refreshToken;
        if (refreshToken) {
            const refreshTokenExists = yield refreshToken_1.refreshTokenModel.exists({
                token: refreshToken
            });
            if (refreshTokenExists) {
                return res.status(200).json({
                    getRefreshIDSuccess: 'Refresh token ID obtained successfully',
                    refreshID: refreshTokenExists._id.toString()
                });
            }
            else {
                return res.status(404).json({
                    getRefreshIDError: 'Refresh token not found'
                });
            }
        }
        else {
            return res.status(401).json({
                getRefreshIDError: 'Refresh token cookie required'
            });
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            getRefreshIDError: 'An unknown error occurred, please try again later'
        });
    }
}));
// Returns MongoDB IDs of all refresh tokens for active refresh token user_id
authRoutes.get('/refresh-token/all', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _d;
    try {
        const refreshToken = (_d = req.cookies) === null || _d === void 0 ? void 0 : _d.refreshToken;
        if (refreshToken) {
            const refreshTokenExists = yield refreshToken_1.refreshTokenModel.findOne({
                token: refreshToken
            });
            if (refreshTokenExists) {
                const refreshTokens = yield refreshToken_1.refreshTokenModel.find({
                    user_id: refreshTokenExists.user_id
                });
                const refreshTokenIDs = refreshTokens.map((refreshToken) => refreshToken._id.toString());
                return res.status(200).json({
                    getRefreshIDSuccess: 'Refresh token IDs obtained successfully',
                    refreshIDs: refreshTokenIDs
                });
            }
            else {
                return res.status(404).json({
                    getRefreshIDError: 'Refresh token not found'
                });
            }
        }
        else {
            return res.status(401).json({
                getRefreshIDError: 'Refresh token cookie required'
            });
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            getRefreshIDError: 'An unknown error occurred, please try again later'
        });
    }
}));
// Deletes specified refresh token
authRoutes.delete('/refresh-token/id/:refreshID', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _e;
    try {
        const activeRefreshToken = (_e = req.cookies) === null || _e === void 0 ? void 0 : _e.refreshToken;
        const passedRefreshTokenID = req.params.refreshID;
        if (activeRefreshToken) {
            const activeRefreshTokenExists = yield refreshToken_1.refreshTokenModel.findOne({
                token: activeRefreshToken
            });
            const passedRefreshTokenExists = yield refreshToken_1.refreshTokenModel.findOne({
                _id: passedRefreshTokenID
            });
            if (activeRefreshTokenExists && passedRefreshTokenExists) {
                const activeUserID = activeRefreshTokenExists.user_id.toString();
                const passedUserID = passedRefreshTokenExists.user_id.toString();
                if (activeUserID === passedUserID) {
                    yield refreshToken_1.refreshTokenModel.findByIdAndDelete(passedRefreshTokenID);
                    return res.status(200).json({
                        deleteRefreshSuccess: 'Refresh token deleted successfully'
                    });
                }
                else {
                    return res.status(401).json({
                        deleteRefreshError: 'Invalid refresh token'
                    });
                }
            }
            else {
                return res
                    .status(404)
                    .json({ deleteRefreshError: 'Refresh token not found' });
            }
        }
        else {
            return res.status(401).json({
                deleteRefreshError: 'Refresh token cookie required'
            });
        }
    }
    catch (err) {
        if (err instanceof mongoose_1.default.Error.CastError) {
            return res.status(400).json({
                deleteRefreshError: 'Invalid refresh token ID param'
            });
        }
        else {
            console.error(err);
            return res.status(500).json({ deleteRefreshError: 'An error occurred' });
        }
    }
}));
// Deletes active refresh token
authRoutes.delete('/refresh-token/current', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _f;
    try {
        const refreshToken = (_f = req.cookies) === null || _f === void 0 ? void 0 : _f.refreshToken;
        if (refreshToken) {
            const refreshTokenExists = yield refreshToken_1.refreshTokenModel.exists({
                token: refreshToken
            });
            if (refreshTokenExists) {
                yield refreshToken_1.refreshTokenModel.deleteOne({ token: refreshToken });
                return res.status(200).json({
                    deleteRefreshSuccess: 'Refresh token deleted successfully'
                });
            }
            else {
                return res
                    .status(404)
                    .json({ deleteRefreshError: 'Refresh token not found' });
            }
        }
        else {
            return res.status(401).json({
                deleteRefreshError: 'Refresh token cookie required'
            });
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            deleteRefreshError: 'An unknown error occurred, please try again later'
        });
    }
}));
// Deletes all refresh tokens for active refresh token user_id
authRoutes.delete('/refresh-token/all', (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _g;
    try {
        const refreshToken = (_g = req.cookies) === null || _g === void 0 ? void 0 : _g.refreshToken;
        if (refreshToken) {
            const refreshTokenExists = yield refreshToken_1.refreshTokenModel.findOne({
                token: refreshToken
            });
            if (refreshTokenExists) {
                const userID = refreshTokenExists.user_id;
                yield refreshToken_1.refreshTokenModel.deleteMany({
                    user_id: userID
                });
                return res.status(200).json({
                    deleteRefreshSuccess: 'Refresh tokens deleted successfully'
                });
            }
            else {
                return res
                    .status(404)
                    .json({ deleteRefreshError: 'Refresh token not found' });
            }
        }
        else {
            return res.status(401).json({
                deleteRefreshError: 'Refresh token cookie required'
            });
        }
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            deleteRefreshError: 'An unknown error occurred, please try again later'
        });
    }
}));
authRoutes.delete('/user', csrf_1.csrfMiddleware, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        if (!(email && password)) {
            return res
                .status(400)
                .json({ deleteUserError: 'Email and password required' });
        }
        const user = yield user_1.userModel.findOne({ email });
        if (user && (yield user.validPassword(password))) {
            yield user_1.userModel.deleteOne({ _id: user._id });
            yield refreshToken_1.refreshTokenModel.deleteMany({ user_id: user._id });
            yield emailVerificationToken_1.emailVerificationTokenModel.deleteMany({ user_id: user._id });
            yield passwordResetToken_1.passwordResetTokenModel.deleteMany({ user_id: user._id });
            yield (0, queryNeo4j_1.default)(req.app.locals.driver, 'MATCH (u:User {email: $email}) DETACH DELETE u', { email });
            res.cookie('accessToken', {}, Object.assign(Object.assign({}, AUTH_COOKIE_OPTIONS), { maxAge: 0 }));
            res.cookie('refreshToken', {}, Object.assign(Object.assign({}, AUTH_COOKIE_OPTIONS), { maxAge: 0 }));
            res.cookie('csrfToken', {}, Object.assign(Object.assign({}, CSRF_COOKIE_OPTIONS), { maxAge: 0 }));
            return res
                .status(200)
                .json({ deleteUserSuccess: 'User deleted successfully' });
        }
        return res.status(401).json({ deleteUserError: 'Invalid credentials' });
    }
    catch (err) {
        console.error(err);
        return res.status(500).json({ deleteUserError: 'An error occurred' });
    }
}));
//# sourceMappingURL=auth.js.map