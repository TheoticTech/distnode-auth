// Standard library
import crypto from 'crypto'

// Third party
import mongoose from 'mongoose'

// Configurations
import {
  PASSWORD_RESET_TOKEN_LENGTH,
  PASSWORD_RESET_TOKEN_TTL
} from '../config'

const passwordResetToken = () => {
  return crypto
    .randomBytes(parseInt(PASSWORD_RESET_TOKEN_LENGTH))
    .toString('hex')
}

const passwordResetTokenSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
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
    index: { expires: PASSWORD_RESET_TOKEN_TTL }
  }
})

const passwordResetTokenModel = mongoose.model(
  'passwordResetToken',
  passwordResetTokenSchema
)

export { passwordResetTokenModel }
