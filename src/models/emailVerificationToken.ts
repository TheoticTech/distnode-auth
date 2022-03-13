// Standard library
import crypto from 'crypto'

// Third party
import mongoose from 'mongoose'

// Configurations
import { VERIFICATION_TOKEN_LENGTH, VERIFICATION_TOKEN_TTL } from '../config'

const emailVerificationToken = () => {
  return crypto.randomBytes(parseInt(VERIFICATION_TOKEN_LENGTH)).toString('hex')
}

const emailVerificationTokenSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
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
    index: { expires: VERIFICATION_TOKEN_TTL }
  }
})

const emailVerificationTokenModel = mongoose.model(
  'emailVerificationToken',
  emailVerificationTokenSchema
)

export { emailVerificationTokenModel }
