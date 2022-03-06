// Third party
import express, { CookieOptions } from 'express'
import jwt from 'jsonwebtoken'

// Local
import queryNeo4j from '../utils/queryNeo4j'
import { refreshTokenModel } from '../models/refreshToken'
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

      if (
        /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,64}$/.test(
          password
        ) === false
      ) {
        return res.status(400).json({
          registrationError:
            'Password must contain at least one number, ' +
            'one uppercase letter, ' +
            'one lowercase letter, ' +
            'one special character, ' +
            'and be 8 to 64 characters long'
        })
      }

      if (/^([a-zA-Z0-9]){1,24}$/.test(username) === false) {
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
        'CREATE (p:Person {' +
          'firstName: $firstName, ' +
          'lastName: $lastName, ' +
          'username: $username, ' +
          'email: $email' +
          '}) RETURN p',
        { firstName, lastName, username, email }
      )

      const accessToken = jwt.sign(
        { user_id: user._id },
        JWT_ACCESS_TOKEN_SECRET,
        {
          expiresIn: JWT_ACCESS_TOKEN_TTL
        }
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

      return res.status(401).json({ loginError: 'Invalid credentials' })
    } catch (err) {
      console.error(err)
      return res.status(500).json({ loginError: 'An error occurred' })
    }
  }
)

authRoutes.get(
  '/refresh-access-token',
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

        const isValidToken = jwt.verify(refreshToken, JWT_REFRESH_TOKEN_SECRET)

        if (existingRefreshToken && isValidToken) {
          const accessToken = jwt.sign(
            { user_id: existingRefreshToken.user_id },
            JWT_ACCESS_TOKEN_SECRET,
            { expiresIn: JWT_ACCESS_TOKEN_TTL }
          )

          res.cookie('accessToken', accessToken, AUTH_COOKIE_OPTIONS)

          return res
            .status(200)
            .json({ refreshSuccess: 'Access token refreshed successfully' })
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

authRoutes.get(
  '/refresh-csrf-token',
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

        const isValidToken = jwt.verify(refreshToken, JWT_REFRESH_TOKEN_SECRET)

        if (existingRefreshToken && isValidToken) {
          const csrfToken = jwt.sign(
            { user_id: existingRefreshToken.user_id },
            CSRF_TOKEN_SECRET,
            {
              expiresIn: CSRF_TOKEN_TTL
            }
          )

          res.cookie('csrfToken', csrfToken, CSRF_COOKIE_OPTIONS)

          return res
            .status(200)
            .json({ refreshSuccess: 'CSRF token refreshed successfully' })
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

authRoutes.post(
  '/logout',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      res.cookie('accessToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
      res.cookie('refreshToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })

      const refreshToken = req.cookies?.refreshToken

      if (refreshToken) {
        await refreshTokenModel.deleteOne({ token: refreshToken })
      }

      return res
        .status(200)
        .json({ logoutSuccess: 'User logged out successfully' })
    } catch (err) {
      console.error(err)
      return res.status(500).json({ logoutError: 'An error occurred' })
    }
  }
)

authRoutes.delete(
  '/delete-refresh-token',
  async (
    req: express.Request,
    res: express.Response
  ): Promise<express.Response> => {
    try {
      const { refreshToken } = req.body

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
      }

      return res
        .status(400)
        .json({ deleteRefreshError: 'Refresh token required' })
    } catch (err) {
      console.error(err)
      return res.status(500).json({ deleteRefreshError: 'An error occurred' })
    }
  }
)

authRoutes.delete(
  '/delete-user',
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

        await queryNeo4j(
          req.app.locals.driver,
          'MATCH (p:Person {email: $email}) DELETE p',
          { email }
        )

        res.cookie('accessToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })
        res.cookie('refreshToken', {}, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 })

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
