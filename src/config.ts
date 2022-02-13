const ARGON_MEMORY_COST = 16384
const JWT_SECRET = process.env.JWT_SECRET
const JWT_TOKEN_TTL = '7m'
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/test'
const PORT = process.env.PORT || 3001

export { ARGON_MEMORY_COST, JWT_TOKEN_TTL, JWT_SECRET, MONGO_URI, PORT }
