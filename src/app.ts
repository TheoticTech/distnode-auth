// Standard library
import fs from 'fs'
import http from 'http'

// Third party
import cookieParser from 'cookie-parser'
import { createTerminus } from '@godaddy/terminus'
import express from 'express'
import mongoose from 'mongoose'
import neo4j from 'neo4j-driver'

// Local
import { authRoutes } from './routes/auth'
import { corsMiddleware } from './middleware/cors'

// Configurations
import {
  ENVIRONMENT,
  MONGO_CA_CERT,
  MONGO_URI,
  NEO4J_PASSWORD,
  NEO4J_USERNAME,
  NEO4J_URI,
  PORT
} from './config'

// Ensure necessary configurations are set
if ([NEO4J_PASSWORD, NEO4J_USERNAME, NEO4J_URI].some((e) => !e)) {
  console.error('NEO4J_PASSWORD, NEO4J_USERNAME and NEO4J_URI must be set')
  process.exit(1)
}

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
    tlsCAFile: ENVIRONMENT === 'production' ? MONGO_CA_CERT_FILENAME : undefined
  })
  .then(() => {
    console.log('Successfully connected to MongoDB')

    app.locals.driver = neo4j.driver(
      NEO4J_URI,
      neo4j.auth.basic(NEO4J_USERNAME, NEO4J_PASSWORD)
    )

    app.use(corsMiddleware)
    app.use('/auth', authRoutes)

    app.use('*', (req, res) => {
      return res.status(404).send('Route not found')
    })

    const server = http.createServer(app)

    async function onSignal() {
      console.log('\nServer is starting cleanup')
      await mongoose.disconnect()
      console.log('Successfully disconnected from MongoDB')
      await app.locals.driver.close()
      console.log('Successfully closed Neo4j driver')
    }

    async function onHealthCheck() {
      if (mongoose.connection.readyState !== 1) {
        return Promise.reject()
      } else {
        return Promise.resolve()
      }
    }

    createTerminus(server, {
      signals: ['SIGHUP', 'SIGINT', 'SIGTERM'],
      healthChecks: { '/health': onHealthCheck },
      onSignal
    })

    server.listen(PORT, () => {
      console.log('Server running on port:', PORT)
    })
  })
  .catch((error) => {
    console.log('MongoDB connection failed. Exiting now...')
    console.error(error)
    process.exit(1)
  })

export { app }
