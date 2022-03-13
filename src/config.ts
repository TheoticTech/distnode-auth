const ENVIRONMENT = process.env.NODE_ENV || 'development'
const ARGON_MEMORY_COST = 16384
const CSRF_TOKEN_SECRET = process.env.CSRF_TOKEN_SECRET
const CSRF_TOKEN_TTL = '1h'
const DOMAIN_NAME = process.env.DOMAIN_NAME || 'distnode.com'
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3002'
const JWT_ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_TOKEN_SECRET
const JWT_ACCESS_TOKEN_TTL = '30s'
const JWT_REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_TOKEN_SECRET
const JWT_REFRESH_TOKEN_TTL = '7d'
const MONGO_CA_CERT = process.env.MONGO_CA_CERT
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/test'
const NEO4J_USERNAME = process.env.NEO4J_USERNAME
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD
const NEO4J_URI = process.env.NEO4J_URI
const PASSWORD_RESET_TOKEN_LENGTH =
  process.env.PASSWORD_RESET_TOKEN_LENGTH || '256'
const PASSWORD_RESET_TOKEN_TTL = process.env.PASSWORD_RESET_TOKEN_TTL || '15m'
const PORT = process.env.PORT || 3000
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY
const VERIFICATION_TOKEN_LENGTH = process.env.VERIFICATION_TOKEN_LENGTH || '256'
const VERIFICATION_TOKEN_TTL = process.env.VERIFICATION_TOKEN_TTL || '1h'

export {
  ENVIRONMENT,
  ARGON_MEMORY_COST,
  CSRF_TOKEN_SECRET,
  CSRF_TOKEN_TTL,
  DOMAIN_NAME,
  FRONTEND_ORIGIN,
  JWT_ACCESS_TOKEN_SECRET,
  JWT_ACCESS_TOKEN_TTL,
  JWT_REFRESH_TOKEN_SECRET,
  JWT_REFRESH_TOKEN_TTL,
  MONGO_CA_CERT,
  MONGO_URI,
  NEO4J_USERNAME,
  NEO4J_PASSWORD,
  NEO4J_URI,
  PASSWORD_RESET_TOKEN_LENGTH,
  PASSWORD_RESET_TOKEN_TTL,
  PORT,
  SENDGRID_API_KEY,
  VERIFICATION_TOKEN_LENGTH,
  VERIFICATION_TOKEN_TTL
}
