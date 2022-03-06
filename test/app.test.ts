// Third party
import chai from 'chai'
import chaiHttp from 'chai-http'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'

// Local
import { app } from '../src/app'
import { userModel } from '../src/models/user'
import { refreshTokenModel } from '../src/models/refreshToken'

// Configurations
import { CSRF_TOKEN_SECRET } from '../src/config'

chai.use(chaiHttp)
chai.should()

const validRegistrationPayload = {
  firstName: 'John',
  lastName: 'Doe',
  username: 'johndoe',
  email: 'johndoe@distnode.com',
  password: 'P@ssw0rd'
}

// NOTE: App requires a MongoDB connection
describe('Authentication routes', function () {
  describe('POST /auth/register', function () {
    beforeEach(async function () {
      await userModel.deleteMany()
    })

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...missingPasswordPayload } = validRegistrationPayload

    it('should return 201 and set token cookies when supplied proper input', (done) => {
      chai
        .request(app)
        .post('/auth/register')
        .send(validRegistrationPayload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(201)
          res.should.have.cookie('accessToken')
          res.should.have.cookie('refreshToken')
          res.should.have.cookie('csrfToken')
          res.body.should.have.property(
            'registrationSuccess',
            'User created successfully'
          )
          done()
        })
    })

    it('should return 400 if any registration fields are missing', (done) => {
      chai
        .request(app)
        .post('/auth/register')
        .send(missingPasswordPayload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'registrationError',
            'All input is required'
          )
          done()
        })
    })

    it('should return 400 if password is too short', (done) => {
      const payload = {
        ...missingPasswordPayload,
        password: 'P@ssw0r'
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 400 if password is too long', (done) => {
      const payload = {
        ...missingPasswordPayload,
        password: 'P@ssw0rd'.repeat(10)
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 400 if password is missing a number', (done) => {
      const payload = {
        ...missingPasswordPayload,
        password: 'P@ssword'
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 400 if password is missing a lowercase letter', (done) => {
      const payload = {
        ...missingPasswordPayload,
        password: 'PASSW0RD'
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 400 if password is missing an uppercase letter', (done) => {
      const payload = {
        ...missingPasswordPayload,
        password: 'p@ssw0rd'
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 400 if password is missing a special character', (done) => {
      const payload = {
        ...missingPasswordPayload,
        password: 'Passw0rd'
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 400 if username contains special characters', (done) => {
      const payload = {
        firstName: 'John',
        lastName: 'Doe',
        username: 'johndoe!',
        email: 'johndoe@distnode.com',
        password: 'P@ssw0rd'
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 400 if username is longer than 24 characters', (done) => {
      const payload = {
        firstName: 'John',
        lastName: 'Doe',
        username: 'j'.repeat(25),
        email: 'johndoe@distnode.com',
        password: 'P@ssw0rd'
      }
      chai
        .request(app)
        .post('/auth/register')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          done()
        })
    })

    it('should return 409 if username is already taken', (done) => {
      // Create two payloads with the same username
      const firstPayload = {
        firstName: 'John',
        lastName: 'Doe',
        username: 'jd',
        email: 'johndoe@distnode.com',
        password: 'P@ssw0rd'
      }
      const secondPayload = {
        firstName: 'Jane',
        lastName: 'Dawn',
        username: 'jd',
        email: 'janedawn@distnode.com',
        password: 'P@ssw0rd'
      }
      userModel.create(firstPayload).then(() => {
        chai
          .request(app)
          .post('/auth/register')
          .send(secondPayload)
          .end((err, res) => {
            if (err) {
              done(err)
            }
            res.should.have.status(409)
            res.body.should.have.property(
              'registrationError',
              'Username is already in use'
            )
            done()
          })
      })
    })

    it('should return 409 if email is already taken', (done) => {
      // Create two payloads with the same email
      const firstPayload = {
        firstName: 'John',
        lastName: 'Doe',
        username: 'johndoe',
        email: 'jd@distnode.com',
        password: 'P@ssw0rd'
      }
      const secondPayload = {
        firstName: 'Jane',
        lastName: 'Dawn',
        username: 'janedawn',
        email: 'jd@distnode.com',
        password: 'P@ssw0rd'
      }
      userModel.create(firstPayload).then(() => {
        chai
          .request(app)
          .post('/auth/register')
          .send(secondPayload)
          .end((err, res) => {
            if (err) {
              done(err)
            }
            res.should.have.status(409)
            res.body.should.have.property(
              'registrationError',
              'Email is already in use'
            )
            done()
          })
      })
    })
  })

  describe('POST /auth/login', () => {
    beforeEach(async function () {
      await userModel.deleteMany()
    })

    it('should return 200 and set token cookies for valid login', (done) => {
      userModel.create(validRegistrationPayload).then(() => {
        chai
          .request(app)
          .post('/auth/login')
          .send(validRegistrationPayload)
          .end((err, res) => {
            if (err) {
              done(err)
            }
            res.should.have.status(200)
            res.should.have.cookie('accessToken')
            res.should.have.cookie('refreshToken')
            res.should.have.cookie('csrfToken')
            res.body.should.have.property(
              'loginSuccess',
              'User logged in successfully'
            )
            done()
          })
      })
    })

    it('should return 401 for invalid login', (done) => {
      const payload = {
        ...validRegistrationPayload,
        password: 'NotTheP@ssw0rd1'
      }
      userModel.create(validRegistrationPayload).then(() => {
        chai
          .request(app)
          .post('/auth/login')
          .send(payload)
          .end((err, res) => {
            if (err) {
              done(err)
            }
            res.should.have.status(401)
            res.should.not.have.cookie('accessToken')
            res.should.not.have.cookie('refreshToken')
            res.should.not.have.cookie('csrfToken')
            res.body.should.have.property('loginError', 'Invalid credentials')
            done()
          })
      })
    })

    it('should return 400 for missing password', (done) => {
      const payload = {
        ...validRegistrationPayload,
        password: undefined
      }
      chai
        .request(app)
        .post('/auth/login')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.should.not.have.cookie('accessToken')
          res.should.not.have.cookie('refreshToken')
          res.should.not.have.cookie('csrfToken')
          res.body.should.have.property(
            'loginError',
            'Email and password required'
          )
          done()
        })
    })

    it('should return 400 for missing email', (done) => {
      const payload = {
        ...validRegistrationPayload,
        email: undefined
      }
      chai
        .request(app)
        .post('/auth/login')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.should.not.have.cookie('accessToken')
          res.should.not.have.cookie('refreshToken')
          res.should.not.have.cookie('csrfToken')
          res.body.should.have.property(
            'loginError',
            'Email and password required'
          )
          done()
        })
    })

    it('should return 401 for non-existent user', (done) => {
      const payload = {
        ...validRegistrationPayload,
        email: 'nonexistent@distnode.com'
      }
      chai
        .request(app)
        .post('/auth/login')
        .send(payload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.should.not.have.cookie('accessToken')
          res.should.not.have.cookie('refreshToken')
          res.should.not.have.cookie('csrfToken')
          res.body.should.have.property('loginError', 'Invalid credentials')
          done()
        })
    })
  })

  describe('POST /auth/refresh-access-token', () => {
    beforeEach(async function () {
      await userModel.deleteMany()
    })

    it('should return 200 and set token cookies for valid refresh', (done) => {
      userModel.create(validRegistrationPayload).then(() => {
        const agent = chai.request.agent(app)

        agent
          .post('/auth/login')
          .send(validRegistrationPayload)
          .then((loginRes) => {
            loginRes.should.have.cookie('accessToken')
            loginRes.should.have.cookie('refreshToken')
            loginRes.should.have.cookie('csrfToken')

            return agent
              .get('/auth/refresh-access-token')
              .then((refreshRes) => {
                refreshRes.should.have.status(200)
                refreshRes.should.have.cookie('accessToken')
                refreshRes.body.should.have.property(
                  'refreshSuccess',
                  'Access token refreshed successfully'
                )
                done()
              })
          })
          .catch((err) => {
            done(err)
          })
          .finally(() => {
            agent.close()
          })
      })
    })

    it('should return 401 if no refresh token provided', (done) => {
      const agent = chai.request.agent(app)

      agent
        .get('/auth/refresh-access-token')
        .then((res) => {
          res.should.have.status(401)
          res.should.have.not.have.cookie('accessToken')
          res.should.have.not.have.cookie('csrfToken')
          res.body.should.have.property(
            'refreshError',
            'Refresh token required'
          )
          done()
        })
        .catch((err) => {
          done(err)
        })
        .finally(() => {
          agent.close()
        })
    })

    it('should return 401 if invalid refresh token provided', (done) => {
      userModel.create(validRegistrationPayload).then(() => {
        const agent = chai.request.agent(app)

        agent
          .get('/auth/refresh-access-token')
          .set('Cookie', 'refreshToken=invalid-token')
          .then((refreshRes) => {
            refreshRes.should.have.status(401)
            refreshRes.should.not.have.cookie('accessToken')
            refreshRes.should.not.have.cookie('refreshToken')
            refreshRes.should.not.have.cookie('csrfToken')
            refreshRes.body.should.have.property(
              'refreshError',
              'Invalid refresh token'
            )
            done()
          })
          .catch((err) => {
            done(err)
          })
          .finally(() => {
            agent.close()
          })
      })
    })
  })

  describe('POST /auth/refresh-csrf-token', () => {
    beforeEach(async function () {
      await userModel.deleteMany()
    })

    it('should return 200 and set token cookies for valid refresh', (done) => {
      userModel.create(validRegistrationPayload).then(() => {
        const agent = chai.request.agent(app)

        agent
          .post('/auth/login')
          .send(validRegistrationPayload)
          .then((loginRes) => {
            loginRes.should.have.cookie('accessToken')
            loginRes.should.have.cookie('refreshToken')
            loginRes.should.have.cookie('csrfToken')

            return agent.get('/auth/refresh-csrf-token').then((refreshRes) => {
              refreshRes.should.have.status(200)
              refreshRes.should.have.cookie('csrfToken')
              refreshRes.body.should.have.property(
                'refreshSuccess',
                'CSRF token refreshed successfully'
              )
              done()
            })
          })
          .catch((err) => {
            done(err)
          })
          .finally(() => {
            agent.close()
          })
      })
    })

    it('should return 401 if no refresh token provided', (done) => {
      const agent = chai.request.agent(app)

      agent
        .get('/auth/refresh-csrf-token')
        .then((res) => {
          res.should.have.status(401)
          res.should.have.not.have.cookie('accessToken')
          res.should.have.not.have.cookie('csrfToken')
          res.body.should.have.property(
            'refreshError',
            'Refresh token required'
          )
          done()
        })
        .catch((err) => {
          done(err)
        })
        .finally(() => {
          agent.close()
        })
    })

    it('should return 401 if invalid refresh token provided', (done) => {
      userModel.create(validRegistrationPayload).then(() => {
        const agent = chai.request.agent(app)

        agent
          .get('/auth/refresh-csrf-token')
          .set('Cookie', 'refreshToken=invalid-token')
          .then((refreshRes) => {
            refreshRes.should.have.status(401)
            refreshRes.should.not.have.cookie('accessToken')
            refreshRes.should.not.have.cookie('refreshToken')
            refreshRes.should.not.have.cookie('csrfToken')
            refreshRes.body.should.have.property(
              'refreshError',
              'Invalid refresh token'
            )
            done()
          })
          .catch((err) => {
            done(err)
          })
          .finally(() => {
            agent.close()
          })
      })
    })
  })

  describe('POST /auth/logout', () => {
    it('should return 200 and delete refresh token if exists', (done) => {
      refreshTokenModel
        .create({
          token: 'token',
          user_id: new mongoose.Types.ObjectId()
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .post('/auth/logout')
            .set('Cookie', `refreshToken=${token.token}`)
            .send({})
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(200)
              res.body.should.have.property(
                'logoutSuccess',
                'User logged out successfully'
              )

              refreshTokenModel
                .exists({
                  token: token.token
                })
                .then((exists) => {
                  chai.expect(exists).to.be.null
                  done()
                })
                .catch((err) => {
                  done(err)
                })
            })
        })
        .catch((err) => {
          done(err)
        })
    })

    it('should return 200 even if refresh token does not exist', (done) => {
      chai
        .request(app)
        .post('/auth/logout')
        .set('Cookie', 'refreshToken=invalid-token')
        .send({})
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(200)
          res.body.should.have.property(
            'logoutSuccess',
            'User logged out successfully'
          )
          done()
        })
    })

    it('should return 200 even if refresh token is not provided', (done) => {
      chai
        .request(app)
        .post('/auth/logout')
        .send({})
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(200)
          res.body.should.have.property(
            'logoutSuccess',
            'User logged out successfully'
          )
          done()
        })
    })
  })

  describe('DELETE /auth/delete-refresh-token', () => {
    beforeEach(async function () {
      await refreshTokenModel.deleteMany()
    })

    it('should return 200 if valid refresh token provided and deleted', (done) => {
      refreshTokenModel
        .create({
          token: 'token',
          user_id: new mongoose.Types.ObjectId()
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .delete('/auth/delete-refresh-token')
            .send({ refreshToken: token.token })
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(200)
              res.body.should.have.property(
                'deleteRefreshSuccess',
                'Refresh token deleted successfully'
              )

              refreshTokenModel
                .exists({
                  token: token.token
                })
                .then((exists) => {
                  chai.expect(exists).to.be.null
                  done()
                })
                .catch((err) => {
                  done(err)
                })
            })
        })
        .catch((err) => {
          done(err)
        })
    })

    it('should return 404 if refresh token not found', (done) => {
      chai
        .request(app)
        .delete('/auth/delete-refresh-token')
        .send({ refreshToken: 'non-existent-token' })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(404)
          res.body.should.have.property(
            'deleteRefreshError',
            'Refresh token not found'
          )
          done()
        })
    })

    it('should return 400 if refresh token not provided', (done) => {
      chai
        .request(app)
        .delete('/auth/delete-refresh-token')
        .send({})
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'deleteRefreshError',
            'Refresh token required'
          )
          done()
        })
    })
  })

  describe('DELETE /auth/delete-user', () => {
    beforeEach(async function () {
      await userModel.deleteMany()
      await refreshTokenModel.deleteMany()
    })

    it('should return 200 and delete user and refresh tokens if they exist', (done) => {
      userModel.create(validRegistrationPayload).then((user) => {
        const agent = chai.request.agent(app)

        agent
          .post('/auth/login')
          .send(validRegistrationPayload)
          .then((loginRes) => {
            loginRes.should.have.cookie('accessToken')
            loginRes.should.have.cookie('refreshToken')
            loginRes.should.have.cookie('csrfToken')
            const csrfToken = loginRes['headers']['set-cookie']
              .filter((cookie) => cookie.includes('csrfToken'))[0]
              .split(';')[0]
              .split('=')[1]

            return agent
              .delete('/auth/delete-user')
              .send({ ...validRegistrationPayload, csrfToken })
              .then((deleteRes) => {
                deleteRes.should.have.status(200)
                deleteRes.should.not.have.cookie('accessToken')
                deleteRes.should.not.have.cookie('refreshToken')
                deleteRes.should.not.have.cookie('csrfToken')
                deleteRes.body.should.have.property(
                  'deleteUserSuccess',
                  'User deleted successfully'
                )

                userModel
                  .exists({
                    user_id: user._id
                  })
                  .then((userExists) => {
                    chai.expect(userExists).to.be.null

                    refreshTokenModel
                      .exists({
                        user_id: user._id
                      })
                      .then((refreshTokenExists) => {
                        chai.expect(refreshTokenExists).to.be.null
                        done()
                      })
                      .catch((err) => {
                        done(err)
                      })
                  })
                  .catch((err) => {
                    done(err)
                  })
              })
          })
          .catch((err) => {
            done(err)
          })
          .finally(() => {
            agent.close()
          })
      })
    })

    it('should return 401 if CSRF token missing from cookies', (done) => {
      const csrfToken = jwt.sign({ user_id: 'johndoe' }, CSRF_TOKEN_SECRET, {
        expiresIn: '10s'
      })

      chai
        .request(app)
        .delete('/auth/delete-user')
        .send({ csrfToken })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property(
            'csrfError',
            'CSRF cookie and body token required'
          )
          done()
        })
    })

    it('should return 401 if CSRF token missing from body', (done) => {
      const csrfToken = jwt.sign({ user_id: 'johndoe' }, CSRF_TOKEN_SECRET, {
        expiresIn: '10s'
      })

      chai
        .request(app)
        .delete('/auth/delete-user')
        .set('Cookie', [`csrfToken=${csrfToken}`])
        .send({})
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property(
            'csrfError',
            'CSRF cookie and body token required'
          )
          done()
        })
    })

    it('should return 401 if CSRF cookie and body mismatch', (done) => {
      const csrfToken = jwt.sign({ user_id: 'johndoe' }, CSRF_TOKEN_SECRET, {
        expiresIn: '10s'
      })

      chai
        .request(app)
        .delete('/auth/delete-user')
        .set('Cookie', [`csrfToken=${csrfToken}`])
        .send({ csrfToken: 'non-existent-token' })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property('csrfError', 'CSRF token mismatch')
          done()
        })
    })

    it('should return 401 if CSRF token expired', (done) => {
      const csrfToken = jwt.sign({ user_id: 'johndoe' }, CSRF_TOKEN_SECRET, {
        expiresIn: '-1s'
      })

      chai
        .request(app)
        .delete('/auth/delete-user')
        .set('Cookie', [`csrfToken=${csrfToken}`])
        .send({ csrfToken })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property('csrfError', 'Expired CSRF token')
          done()
        })
    })

    it('should return 401 if CSRF token is invalid', (done) => {
      chai
        .request(app)
        .delete('/auth/delete-user')
        .set('Cookie', ['csrfToken=invalid-token'])
        .send({ csrfToken: 'invalid-token' })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property('csrfError', 'Invalid CSRF token')
          done()
        })
    })

    it('should return 400 if user data not provided', (done) => {
      const csrfToken = jwt.sign({ user_id: 'johndoe' }, CSRF_TOKEN_SECRET, {
        expiresIn: '10s'
      })
      chai
        .request(app)
        .delete('/auth/delete-user')
        .set('Cookie', [`csrfToken=${csrfToken}`])
        .send({ csrfToken })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'deleteUserError',
            'Email and password required'
          )
          done()
        })
    })

    it('should return 401 if user does not exist', (done) => {
      const csrfToken = jwt.sign({ user_id: 'johndoe' }, CSRF_TOKEN_SECRET, {
        expiresIn: '10s'
      })

      chai
        .request(app)
        .delete('/auth/delete-user')
        .set('Cookie', [`csrfToken=${csrfToken}`])
        .send({ ...validRegistrationPayload, csrfToken })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property(
            'deleteUserError',
            'Invalid credentials'
          )
          done()
        })
    })
  })

  describe('GET /doesnt-exist', () => {
    it('should return 404 if route does not exist', (done) => {
      chai
        .request(app)
        .get('/doesnt-exist')
        .send({})
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(404)
          res.text.should.equal('Route not found')
          done()
        })
    })
  })
})
