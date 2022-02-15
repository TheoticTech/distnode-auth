// Third party
import express, { CookieOptions } from 'express'
import jwt from 'jsonwebtoken'

// Local
import { userModel } from '../models/user'
import { refreshTokenModel } from '../models/refreshToken'

// Configurations
import {
    ENVIRONMENT,
    JWT_ACCESS_TOKEN_SECRET,
    JWT_ACCESS_TOKEN_TTL,
    JWT_REFRESH_TOKEN_SECRET,
    JWT_REFRESH_TOKEN_TTL
} from '../config'

// Constants
const COOKIE_OPTIONS: CookieOptions = {
    httpOnly: true,
    secure: ENVIRONMENT === 'production',
    sameSite: 'strict'
}

if (!JWT_ACCESS_TOKEN_SECRET || !JWT_REFRESH_TOKEN_SECRET) {
    console.error(
        'JWT_ACCESS_TOKEN_SECRET and JWT_REFRESH_TOKEN_SECRET must be set'
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
                return res.status(400).send('All input is required')
            }

            if (await userModel.findOne({ email })) {
                return res.status(409).send('Email is already in use')
            }

            if (await userModel.findOne({ username })) {
                return res.status(409).send('Username is already in use')
            }

            if (
                /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,64}$/.test(
                    password
                ) === false
            ) {
                return res
                    .status(400)
                    .send(
                        'Password must contain at least one number, ' +
                            'one uppercase letter, ' +
                            'one lowercase letter, ' +
                            'one special character, ' +
                            'and be 8 to 64 characters long'
                    )
            }

            if (/^([a-zA-Z0-9]){1,24}$/.test(username) === false) {
                return res
                    .status(400)
                    .send(
                        'Username must only contain numbers, letters, ' +
                            'and a maximum of 24 characters'
                    )
            }

            const user = await new userModel({
                firstName,
                lastName,
                username,
                email: email.toLowerCase(),
                password
            }).save()

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

            await refreshTokenModel.create({
                user_id: user._id,
                token: refreshToken
            })

            res.cookie('accessToken', accessToken, COOKIE_OPTIONS)
            res.cookie('refreshToken', refreshToken, COOKIE_OPTIONS)

            return res.status(201).send('User created successfully')
        } catch (err) {
            console.error(err)
            return res.status(500).send('An error occurred')
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
                return res.status(400).send('Email and password required')
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

                await refreshTokenModel.create({
                    user_id: user._id,
                    token: refreshToken
                })

                res.cookie('accessToken', accessToken, COOKIE_OPTIONS)
                res.cookie('refreshToken', refreshToken, COOKIE_OPTIONS)

                return res.status(200).send('User logged in successfully')
            }

            return res.status(401).send('Invalid credentials')
        } catch (err) {
            console.error(err)
            return res.status(500).send('An error occurred')
        }
    }
)

authRoutes.post(
    '/refresh',
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

                const isValidToken = jwt.verify(
                    refreshToken,
                    JWT_REFRESH_TOKEN_SECRET
                )

                if (existingRefreshToken && isValidToken) {
                    const accessToken = jwt.sign(
                        { user_id: existingRefreshToken.user_id },
                        JWT_ACCESS_TOKEN_SECRET,
                        { expiresIn: JWT_ACCESS_TOKEN_TTL }
                    )

                    res.cookie('accessToken', accessToken, COOKIE_OPTIONS)

                    return res.status(200).send('Access token refreshed')
                }
            } else {
                return res.status(401).send('Refresh token required')
            }

            return res.status(401).send('Invalid refresh token')
        } catch (err) {
            if (err instanceof jwt.JsonWebTokenError) {
                return res.status(401).send('Invalid refresh token')
            } else {
                console.error(err)
                return res.status(500).send('An error occurred')
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
            res.cookie('accessToken', {}, { ...COOKIE_OPTIONS, maxAge: 0 })
            res.cookie('refreshToken', {}, { ...COOKIE_OPTIONS, maxAge: 0 })

            const refreshToken = req.cookies?.refreshToken

            if (refreshToken) {
                await refreshTokenModel.deleteOne({ token: refreshToken })
            }

            return res.status(200).send('User logged out successfully')
        } catch (err) {
            console.error(err)
            return res.status(500).send('An error occurred')
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
                    return res
                        .status(200)
                        .send('Refresh token deleted successfully')
                } else {
                    return res.status(404).send('Refresh token not found')
                }
            }

            return res.status(400).send('Refresh token required')
        } catch (err) {
            console.error(err)
            return res.status(500).send('An error occurred')
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
                return res.status(400).send('Email and password required')
            }

            const user = await userModel.findOne({ email })

            if (user && (await user.validPassword(password))) {
                await userModel.deleteOne({ _id: user._id })
                await refreshTokenModel.deleteMany({ user_id: user._id })

                res.cookie('accessToken', {}, { ...COOKIE_OPTIONS, maxAge: 0 })
                res.cookie('refreshToken', {}, { ...COOKIE_OPTIONS, maxAge: 0 })

                return res.status(200).send('User deleted successfully')
            }

            return res.status(401).send('Invalid credentials')
        } catch (err) {
            console.error(err)
            return res.status(500).send('An error occurred')
        }
    }
)

export { authRoutes }
