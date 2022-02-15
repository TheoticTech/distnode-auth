// Standard library
import fs from 'fs'

// Third party
import cookieParser from 'cookie-parser'
import express from 'express'
import mongoose from 'mongoose'

// Local
import { authRoutes } from './routes/auth'

// Configurations
import { ENVIRONMENT, MONGO_CA_CERT, MONGO_URI, PORT } from './config'

// Constants
const MONGO_CA_CERT_FILENAME = 'mongo-ca-cert.pem'

console.log(`App starting in ${ENVIRONMENT} mode`)

const app = express()
app.use(cookieParser())
app.use(express.json())

if (ENVIRONMENT === 'production') {
    if (!MONGO_CA_CERT) {
        console.error('MONGO_CA_CERT must be set if NODE_ENV === production')
        process.exit(1)
    }
    fs.writeFileSync(MONGO_CA_CERT_FILENAME, MONGO_CA_CERT)
}

mongoose
    .connect(MONGO_URI, {
        // MONGO_CA_CERT can be undefined when NODE_ENV !== production
        tlsCAFile:
            ENVIRONMENT === 'production' ? MONGO_CA_CERT_FILENAME : undefined
    })
    .then(() => {
        console.log('Successfully connected to database')
    })
    .catch((error) => {
        console.log('Database connection failed. Exiting now...')
        console.error(error)
        process.exit(1)
    })

app.use('/auth', authRoutes)

app.use('*', (req, res) => {
    return res.status(404).send('Route not found')
})

app.listen(PORT, () => {
    console.log('Server running on port:', PORT)
})

export { app }
