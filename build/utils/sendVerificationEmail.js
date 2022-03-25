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
// Third party
const mail_1 = __importDefault(require("@sendgrid/mail"));
// Local
const callToActionEmail_1 = __importDefault(require("../templates/callToActionEmail"));
// Configurations
const config_1 = require("../config");
const sendVerificationEmail = (email, token) => __awaiter(void 0, void 0, void 0, function* () {
    const link = `${config_1.FRONTEND_ORIGIN}/auth/verify-email?token=${token}`;
    const html = (0, callToActionEmail_1.default)({
        callToActionlink: link,
        bannerImageURL: 'https://distnode-static-prod.s3.amazonaws.com/distnode-twitter-header.jpg',
        headerText: 'Welcome to DistNode',
        bodyText: 'Please verify your email address to complete your registration.',
        callToActionLink: link,
        callToActionButtonText: 'Verify Email'
    });
    mail_1.default.setApiKey(config_1.SENDGRID_API_KEY);
    const msg = {
        to: email,
        from: 'accounts@distnode.com',
        subject: 'DistNode Email Verification',
        text: `Please verify your email by visting the following link: ${link}`,
        html
    };
    mail_1.default
        .send(msg)
        .then(() => {
        console.log('Email verification sent to:', email);
    })
        .catch((error) => {
        console.error(error.toString());
    });
});
exports.default = sendVerificationEmail;
//# sourceMappingURL=sendVerificationEmail.js.map