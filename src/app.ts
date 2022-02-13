// Third party
import express from 'express'
import mongoose from 'mongoose'

// Local
import { authRoutes } from './routes/auth'

// Configurations
import { MONGO_URI, PORT } from './config'

const app = express()
app.use(express.json())

mongoose
    .connect(MONGO_URI)
    .then(() => {
        console.log('Successfully connected to database')
    })
    .catch((error) => {
        console.log('database connection failed. exiting now...')
        console.error(error)
        process.exit(1)
    })

app.use('/auth', authRoutes)

app.use('*', (req, res) => {
    return res.status(404).send('404 Not Found')
})

app.listen(PORT, () => {
    console.log('Server running at port:', PORT)
})

export { app }
