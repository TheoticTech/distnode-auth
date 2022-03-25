// Third party
import express, { CookieOptions } from 'express'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'

// Local
import { csrfMiddleware } from '../middleware/csrf'
import { emailVerificationTokenModel } from '../models/emailVerificationToken'
import queryNeo4j from '../utils/queryNeo4j'
import { refreshTokenModel } from '../models/refreshToken'
import sendPasswordResetEmail from '../utils/sendPasswordResetEmail'
import sendVerificationEmail from '../utils/sendVerificationEmail'
import { userModel } from '../models/user'

// Configurations
import {
  ENVIRONMENT,
  CSRF_TOKEN_SECRET,
  CSRF_TOKEN_TTL,
  DOMAIN_NAME,
  JWT_ACCESS_TOKEN_SECRET,
  JWT_ACCESS_TOKEN_TTL,
  JWT_REFRESH_TOKEN_SECRET,
  JWT_REFRESH_TOKEN_TTL
} from '../config'
import { passwordResetTokenModel } from '../models/passwordResetToken'

// Constants
const AUTH_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: ENVIRONMENT === 'production',
  sameSite: 'strict',
  domain: ENVIRONMENT === 'production' ? DOMAIN_NAME : undefined
}
const CSRF_COOKIE_OPTIONS: CookieOptions = {
  ...AUTH_COOKIE_OPTIONS,
  httpOnly: false
}
const PASSWORD_REGEX = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,64}$/

// Ensure necessary configurations are set
if (
  [CSRF_TOKEN_SECRET, JWT_ACCESS_TOKEN_SECRET, JWT_REFRESH_TOKEN_SECRET].some(
    (e) => !e
  )
) {
  console.error(
    'CSRF_TOKEN_SECRET, ' +
      'JWT_ACCESS_TOKEN_SECRET and ' +
      'JWT_REFRESH_TOKEN_SECRET must be set'
  )
  process.exit(1)
}

const authRoutes = express.Router()

authRoutes.post(
  '/register',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { firstName, lastName, username, email, password } = req.body

      if (!(firstName && lastName && username && email && password)) {
        return res
          .status(400)
          .json({ registrationError: 'All input is required' })
      }

      if (await userModel.findOne({ email })) {
        return res
          .status(409)
          .json({ registrationError: 'Email is already in use' })
      }

      if (await userModel.findOne({ username })) {
        return res
          .status(409)
          .json({ registrationError: 'Username is already in use' })
      }

      if (!PASSWORD_REGEX.test(password)) {
        return res.status(400).json({
          registrationError:
            'Password must contain at least one number, ' +
            'one uppercase letter, ' +
            'one lowercase letter, ' +
            'one special character, ' +
            'and be 8 to 64 characters long'
        })
      }

      if (!/^([a-zA-Z0-9]){1,24}$/.test(username)) {
        return res.status(400).json({
          registrationError:
            'Username must only contain numbers, letters, ' +
            'and a maximum of 24 characters'
        })
      }

      const user = await new userModel({
        firstName,
        lastName,
        username,
        email: email.toLowerCase(),
        password
      }).save()

      await queryNeo4j(
        req.app.locals.driver,
        'CREATE (u:User {' +
          'userID: $userID, ' +
          'firstName: $firstName, ' +
          'lastName: $lastName, ' +
          'username: $username, ' +
          'email: $email, ' +
          'created_at: TIMESTAMP()' +
          '}) RETURN u',
        { userID: user._id.toString(), firstName, lastName, username, email }
      )

      const verificationToken = await emailVerificationTokenModel.create({
        user_id: user._id
      })

      sendVerificationEmail(user.email, verificationToken.token)

      return res
        .status(201)
        .json({ registrationSuccess: 'User created successfully' })
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        registrationError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

// Used to get new verification email
authRoutes.post(
  '/resend-verification-email',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { email } = req.body

      if (email) {
        const user: any = await userModel.findOne({
          email: email.toLowerCase()
        })
        if (user) {
          if (user.emailVerified) {
            return res.status(400).json({
              resendVerificationError: 'Email is already verified'
            })
          } else {
            // Delete any existing verification tokens for user
            await emailVerificationTokenModel.deleteMany({
              user_id: user._id
            })

            const verificationToken = await emailVerificationTokenModel.create({
              user_id: user._id
            })

            sendVerificationEmail(user.email, verificationToken.token)

            return res.status(200).json({
              resendVerificationSuccess:
                'New verification email sent successfully'
            })
          }
        } else {
          return res
            .status(404)
            .json({ resendVerificationError: 'User not found' })
        }
      } else {
        return res
          .status(400)
          .json({ resendVerificationError: 'Email required' })
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        resendVerificationError:
          'An unknown error occurred, please try again later'
      })
    }
  }
)

// Verify email if provided a valid token
authRoutes.post(
  '/verify-email',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { token } = req.query

      if (!token) {
        return res
          .status(400)
          .json({ verifyEmailError: 'Verification token required' })
      } else {
        const verificationToken = await emailVerificationTokenModel.findOne({
          token
        })

        if (!verificationToken) {
          return res
            .status(400)
            .json({ verifyEmailError: 'Invalid verification token' })
        } else {
          const user = await userModel.findById(verificationToken.user_id)

          if (user) {
            if (user.emailVerified) {
              return res.status(400).json({
                verifyEmailError: 'Email is already verified'
              })
            } else {
              user.emailVerified = true
              await user.save()

              return res
                .status(200)
                .json({ verifyEmailSuccess: 'Email verified successfully' })
            }
          } else {
            return res.status(404).json({ verifyEmailError: 'User not found' })
          }
        }
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        verifyEmailError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

// Used to get new password reset token (if not already exists) and email
authRoutes.get(
  '/password-reset',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { email } = req.query

      if (email) {
        const user = await userModel.findOne({
          email: email.toString().toLowerCase()
        })

        if (user) {
          if (!user.emailVerified) {
            return res.status(400).json({
              passwordResetError:
                'Email must be verified before resetting password'
            })
          } else {
            // Delete any existing password reset tokens for user
            await passwordResetTokenModel.deleteMany({
              user_id: user._id
            })

            const passwordResetToken = await passwordResetTokenModel.create({
              user_id: user._id
            })

            sendPasswordResetEmail(user.email, passwordResetToken.token)

            return res.status(200).json({
              passwordResetSuccess: 'Password reset email sent successfully'
            })
          }
        } else {
          return res.status(404).json({ passwordResetError: 'User not found' })
        }
      } else {
        return res.status(400).json({
          passwordResetError: 'Email is required for password reset'
        })
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        passwordResetError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

// Reset password if provided a valid token
authRoutes.post(
  '/password-reset',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { token } = req.query
      const { password } = req.body

      if (!token) {
        return res
          .status(400)
          .json({ passwordResetError: 'Password reset token required' })
      } else if (!password) {
        return res
          .status(400)
          .json({ passwordResetError: 'New password required' })
      } else if (!PASSWORD_REGEX.test(password)) {
        return res.status(400).json({
          passwordResetError: 'New password does not meet requirements'
        })
      } else {
        const passwordResetToken = await passwordResetTokenModel.findOne({
          token
        })

        if (!passwordResetToken) {
          return res
            .status(400)
            .json({ passwordResetError: 'Invalid password reset token' })
        } else {
          const user = await userModel.findById(passwordResetToken.user_id)

          if (user) {
            user.password = password
            await user.save()

            // Delete reset token as password has now been updated
            await passwordResetTokenModel.deleteMany({
              user_id: user._id
            })

            // Delete any existing refresh tokens for user
            await refreshTokenModel.deleteMany({
              user_id: user._id
            })

            return res
              .status(200)
              .json({ passwordResetSuccess: 'Password reset successfully' })
          } else {
            return res
              .status(404)
              .json({ passwordResetError: 'User not found' })
          }
        }
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        passwordResetError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

authRoutes.post(
  '/login',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { email, password } = req.body

      if (!(email && password)) {
        return res
          .status(400)
          .json({ loginError: 'Email and password required' })
      }

      const user = await userModel.findOne({ email })

      if (user && (await user.validPassword(password))) {
        if (!user.emailVerified) {
          return res.status(401).json({
            loginError: 'Email must be verified before logging in'
          })
        }

        const accessToken = jwt.sign(
          { user_id: user._id },
          JWT_ACCESS_TOKEN_SECRET,
          { expiresIn: JWT_ACCESS_TOKEN_TTL }
        )

        const refreshToken = jwt.sign(
          { user_id: user._id },
          JWT_REFRESH_TOKEN_SECRET,
          {
            expiresIn: JWT_REFRESH_TOKEN_TTL
          }
        )

        const csrfToken = jwt.sign({ user_id: user._id }, CSRF_TOKEN_SECRET, {
          expiresIn: CSRF_TOKEN_TTL
        })

        await refreshTokenModel.create({
          user_id: user._id,
          token: refreshToken
        })

        res.cookie('accessToken', accessToken, AUTH_COOKIE_OPTIONS)
        res.cookie('refreshToken', refreshToken, AUTH_COOKIE_OPTIONS)
        res.cookie('csrfToken', csrfToken, CSRF_COOKIE_OPTIONS)

        return res
          .status(200)
          .json({ loginSuccess: 'User logged in successfully' })
      }

      // If we've reached this point, the email or password was incorrect
      return res.status(401).json({ loginError: 'Invalid credentials' })
    } catch (err) {
      console.error(err)
      return res.status(500).json({ loginError: 'An error occurred' })
    }
  }
)

authRoutes.post(
  '/logout',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const refreshToken = req.cookies?.refreshToken

      // Send expired tokens to the client
      res.cookie('accessToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
      res.cookie('refreshToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
      res.cookie('csrfToken', {}, { ...CSRF_COOKIE_OPTIONS, maxAge: 0 })

      if (refreshToken) {
        await refreshTokenModel.deleteOne({ token: refreshToken })
      }

      // Even if refresh token doesn't exist, client cookies will be expired
      return res
        .status(200)
        .json({ logoutSuccess: 'User logged out successfully' })
    } catch (err) {
      console.error(err)
      return res.status(500).json({ logoutError: 'An error occurred' })
    }
  }
)

// Update access and CSRF tokens
authRoutes.get(
  '/refreshed-tokens',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const refreshToken = req.cookies?.refreshToken

      if (refreshToken) {
        const existingRefreshToken = await refreshTokenModel.findOne({
          token: refreshToken
        })

        const isValidRefreshToken = jwt.verify(
          refreshToken,
          JWT_REFRESH_TOKEN_SECRET
        )

        if (existingRefreshToken && isValidRefreshToken) {
          const accessToken = jwt.sign(
            { user_id: existingRefreshToken.user_id },
            JWT_ACCESS_TOKEN_SECRET,
            { expiresIn: JWT_ACCESS_TOKEN_TTL }
          )

          const csrfToken = jwt.sign(
            { user_id: existingRefreshToken.user_id },
            CSRF_TOKEN_SECRET,
            {
              expiresIn: CSRF_TOKEN_TTL
            }
          )

          res.cookie('accessToken', accessToken, AUTH_COOKIE_OPTIONS)
          res.cookie('csrfToken', csrfToken, CSRF_COOKIE_OPTIONS)

          return res
            .status(200)
            .json({ refreshSuccess: 'Tokens refreshed successfully' })
        }
      } else {
        return res.status(401).json({ refreshError: 'Refresh token required' })
      }

      return res.status(401).json({ refreshError: 'Invalid refresh token' })
    } catch (err) {
      if (err instanceof jwt.JsonWebTokenError) {
        return res.status(401).json({ refreshError: 'Invalid refresh token' })
      } else {
        console.error(err)
        return res.status(500).json({ refreshError: 'An error occurred' })
      }
    }
  }
)

// Returns MongoDB ID of current refresh token
authRoutes.get(
  '/refresh-token/current',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const refreshToken = req.cookies?.refreshToken

      if (refreshToken) {
        const refreshTokenExists = await refreshTokenModel.exists({
          token: refreshToken
        })

        if (refreshTokenExists) {
          return res.status(200).json({
            getRefreshIDSuccess: 'Refresh token ID obtained successfully',
            refreshID: refreshTokenExists._id.toString()
          })
        } else {
          return res.status(404).json({
            getRefreshIDError: 'Refresh token not found'
          })
        }
      } else {
        return res.status(401).json({
          getRefreshIDError: 'Refresh token cookie required'
        })
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        getRefreshIDError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

// Returns MongoDB IDs of all refresh tokens for active refresh token user_id
authRoutes.get(
  '/refresh-token/all',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const refreshToken = req.cookies?.refreshToken

      if (refreshToken) {
        const refreshTokenExists = await refreshTokenModel.findOne({
          token: refreshToken
        })

        if (refreshTokenExists) {
          const refreshTokens = await refreshTokenModel.find({
            user_id: refreshTokenExists.user_id
          })

          const refreshTokenIDs = refreshTokens.map((refreshToken) =>
            refreshToken._id.toString()
          )

          return res.status(200).json({
            getRefreshIDSuccess: 'Refresh token IDs obtained successfully',
            refreshIDs: refreshTokenIDs
          })
        } else {
          return res.status(404).json({
            getRefreshIDError: 'Refresh token not found'
          })
        }
      } else {
        return res.status(401).json({
          getRefreshIDError: 'Refresh token cookie required'
        })
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        getRefreshIDError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

// Deletes specified refresh token
authRoutes.delete(
  '/refresh-token/id/:refreshID',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const activeRefreshToken = req.cookies?.refreshToken
      const passedRefreshTokenID = req.params.refreshID

      if (activeRefreshToken) {
        const activeRefreshTokenExists = await refreshTokenModel.findOne({
          token: activeRefreshToken
        })

        const passedRefreshTokenExists = await refreshTokenModel.findOne({
          _id: passedRefreshTokenID
        })

        if (activeRefreshTokenExists && passedRefreshTokenExists) {
          const activeUserID = activeRefreshTokenExists.user_id.toString()
          const passedUserID = passedRefreshTokenExists.user_id.toString()

          if (activeUserID === passedUserID) {
            await refreshTokenModel.findByIdAndDelete(passedRefreshTokenID)
            return res.status(200).json({
              deleteRefreshSuccess: 'Refresh token deleted successfully'
            })
          } else {
            return res.status(401).json({
              deleteRefreshError: 'Invalid refresh token'
            })
          }
        } else {
          return res
            .status(404)
            .json({ deleteRefreshError: 'Refresh token not found' })
        }
      } else {
        return res.status(401).json({
          deleteRefreshError: 'Refresh token cookie required'
        })
      }
    } catch (err) {
      if (err instanceof mongoose.Error.CastError) {
        return res.status(400).json({
          deleteRefreshError: 'Invalid refresh token ID param'
        })
      } else {
        console.error(err)
        return res.status(500).json({ deleteRefreshError: 'An error occurred' })
      }
    }
  }
)

// Deletes active refresh token
authRoutes.delete(
  '/refresh-token/current',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const refreshToken = req.cookies?.refreshToken

      if (refreshToken) {
        const refreshTokenExists = await refreshTokenModel.exists({
          token: refreshToken
        })

        if (refreshTokenExists) {
          await refreshTokenModel.deleteOne({ token: refreshToken })
          return res.status(200).json({
            deleteRefreshSuccess: 'Refresh token deleted successfully'
          })
        } else {
          return res
            .status(404)
            .json({ deleteRefreshError: 'Refresh token not found' })
        }
      } else {
        return res.status(401).json({
          deleteRefreshError: 'Refresh token cookie required'
        })
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        deleteRefreshError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

// Deletes all refresh tokens for active refresh token user_id
authRoutes.delete(
  '/refresh-token/all',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const refreshToken = req.cookies?.refreshToken

      if (refreshToken) {
        const refreshTokenExists = await refreshTokenModel.findOne({
          token: refreshToken
        })

        if (refreshTokenExists) {
          const userID = refreshTokenExists.user_id
          await refreshTokenModel.deleteMany({
            user_id: userID
          })

          return res.status(200).json({
            deleteRefreshSuccess: 'Refresh tokens deleted successfully'
          })
        } else {
          return res
            .status(404)
            .json({ deleteRefreshError: 'Refresh token not found' })
        }
      } else {
        return res.status(401).json({
          deleteRefreshError: 'Refresh token cookie required'
        })
      }
    } catch (err) {
      console.error(err)
      return res.status(500).json({
        deleteRefreshError: 'An unknown error occurred, please try again later'
      })
    }
  }
)

authRoutes.delete(
  '/user',
  csrfMiddleware,
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { email, password } = req.body

      if (!(email && password)) {
        return res
          .status(400)
          .json({ deleteUserError: 'Email and password required' })
      }

      const user = await userModel.findOne({ email })

      if (user && (await user.validPassword(password))) {
        await userModel.deleteOne({ _id: user._id })
        await refreshTokenModel.deleteMany({ user_id: user._id })
        await emailVerificationTokenModel.deleteMany({ user_id: user._id })
        await passwordResetTokenModel.deleteMany({ user_id: user._id })

        await queryNeo4j(
          req.app.locals.driver,
          'MATCH (u:User {email: $email}) DETACH DELETE u',
          { email }
        )

        res.cookie('accessToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
        res.cookie('refreshToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
        res.cookie('csrfToken', {}, { ...CSRF_COOKIE_OPTIONS, maxAge: 0 })

        return res
          .status(200)
          .json({ deleteUserSuccess: 'User deleted successfully' })
      }

      return res.status(401).json({ deleteUserError: 'Invalid credentials' })
    } catch (err) {
      console.error(err)
      return res.status(500).json({ deleteUserError: 'An error occurred' })
    }
  }
)

export { authRoutes }
