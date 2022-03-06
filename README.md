# Getting Started

## Prerequisites
This application requires a MongoDB database, configured by setting a
`MONGO_URI` environment variable. By default, the [config file](./src/config.ts)
sets the MongoDB URI to `mongodb://localhost:27017/test`.

This application also requires a Neo4j database, configured by setting
`NEO4J_URI`, `NEO4J_USERNAME` and `NEO4J_PASSWORD` environment variables.
```sh
export NEO4J_USERNAME='your-neo4j-username'
export NEO4J_PASSWORD='your-neo4j-password'
export NEO4J_URI='neo4j+s://your-neo4j-uri.io:7687'
```

Additionally, this application requires three JWT secrets, configured by
setting `CSRF_TOKEN_SECRET`, `JWT_ACCESS_TOKEN_SECRET` and `JWT_REFRESH_TOKEN_SECRET` 
environment variables. For development and testing, the following can be used:
```sh
export CSRF_TOKEN_SECRET='super-secret-key-0'
export JWT_ACCESS_TOKEN_SECRET='super-secret-key-1'
export JWT_REFRESH_TOKEN_SECRET='super-secret-key-2'
```

## Installation
```sh
npm i
```

## Running in Production
```sh
npm start
```

## Running in Development
```sh
npm run dev
```

## Running Tests
```sh
npm test
```

## Running Test Coverage
```sh
npm run coverage
```

## [Helpful Examples](./rest/auth.rest)
