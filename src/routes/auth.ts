// Third party
import express from 'express'
import jwt from 'jsonwebtoken'

// Local
import { userModel } from '../models/user'

// Configurations
import { JWT_TOKEN_TTL, JWT_SECRET } from '../config'

if (!JWT_SECRET) {
    console.error('JWT_SECRET is not set')
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
                return res.status(409).send('Email is already taken')
            }

            if (await userModel.findOne({ username })) {
                return res.status(409).send('Username is already taken')
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

            const token = jwt.sign({ user_id: user._id, email }, JWT_SECRET, {
                expiresIn: JWT_TOKEN_TTL
            })

            return res.status(201).send({ token })
        } catch (err) {
            console.log(err)
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

            if (user && (await user.validPassword(req.body.password))) {
                const token = jwt.sign(
                    { user_id: user._id, email },
                    JWT_SECRET,
                    { expiresIn: JWT_TOKEN_TTL }
                )

                return res.status(200).send({token})
            }

            return res.status(401).send('Invalid credentials')
        } catch (err) {
            console.log(err)
        }
    }
)

export { authRoutes }
