const ENVIRONMENT = process.env.NODE_ENV || 'development'
const ARGON_MEMORY_COST = 16384
const DOMAIN_NAME = process.env.DOMAIN_NAME || 'distnode.com'
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3002'
const JWT_ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_TOKEN_SECRET
const JWT_ACCESS_TOKEN_TTL = '30s'
const JWT_REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_TOKEN_SECRET
const JWT_REFRESH_TOKEN_TTL = '7d'
const MONGO_CA_CERT = process.env.MONGO_CA_CERT
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/test'
const PORT = process.env.PORT || 3000

export {
    ENVIRONMENT,
    ARGON_MEMORY_COST,
    DOMAIN_NAME,
    FRONTEND_ORIGIN,
    JWT_ACCESS_TOKEN_SECRET,
    JWT_ACCESS_TOKEN_TTL,
    JWT_REFRESH_TOKEN_SECRET,
    JWT_REFRESH_TOKEN_TTL,
    MONGO_CA_CERT,
    MONGO_URI,
    PORT
}
