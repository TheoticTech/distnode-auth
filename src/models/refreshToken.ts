// Third party
import mongoose from 'mongoose'

// Configurations
import { JWT_REFRESH_TOKEN_TTL } from '../config'

const refreshTokenSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  token: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: { expires: JWT_REFRESH_TOKEN_TTL }
  }
})

const refreshTokenModel = mongoose.model('refreshToken', refreshTokenSchema)

export { refreshTokenModel }
