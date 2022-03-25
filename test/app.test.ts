// Third party
import chai from 'chai'
import chaiHttp from 'chai-http'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import sgMail from '@sendgrid/mail'
import sinon from 'sinon'

// Local
import { app } from '../src/app'
import { userModel } from '../src/models/user'
import { refreshTokenModel } from '../src/models/refreshToken'
import { emailVerificationTokenModel } from '../src/models/emailVerificationToken'
import { passwordResetTokenModel } from '../src/models/passwordResetToken'

// Configurations
import { CSRF_TOKEN_SECRET } from '../src/config'

// Setup Chai
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
  before(async function () {
    await userModel.deleteMany()
    await refreshTokenModel.deleteMany()
  })

  describe('POST /auth/register', function () {
    let sendStub: sinon.SinonStub

    beforeEach(() => {
      sendStub = sinon.stub(sgMail, 'send')
    })

    afterEach(async function () {
      await userModel.deleteMany()
      await emailVerificationTokenModel.deleteMany()
      sendStub.restore()
    })

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...missingPasswordPayload } = validRegistrationPayload

    it('should return 201 and send verification email when supplied proper input', (done) => {
      chai
        .request(app)
        .post('/auth/register')
        .send(validRegistrationPayload)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(201)
          res.should.not.have.cookie('accessToken')
          res.should.not.have.cookie('refreshToken')
          res.should.not.have.cookie('csrfToken')
          res.body.should.have.property(
            'registrationSuccess',
            'User created successfully'
          )
          sinon.assert.calledWithMatch(sendStub, {
            to: validRegistrationPayload.email,
            from: 'accounts@distnode.com'
          })
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

  describe('POST /auth/resend-verification-email', () => {
    let sendStub: sinon.SinonStub

    beforeEach(() => {
      sendStub = sinon.stub(sgMail, 'send')
    })

    afterEach(async function () {
      await userModel.deleteMany()
      await refreshTokenModel.deleteMany()
      await emailVerificationTokenModel.deleteMany()
      sendStub.restore()
    })

    it('should return 200 if valid refresh token provided and email sent', (done) => {
      userModel.create(validRegistrationPayload).then((user) => {
        chai
          .request(app)
          .post('/auth/resend-verification-email')
          .send({ email: user.email })
          .end((err, res) => {
            if (err) {
              done(err)
            }
            res.should.have.status(200)
            res.body.should.have.property(
              'resendVerificationSuccess',
              'New verification email sent successfully'
            )

            sinon.assert.calledWithMatch(sendStub, {
              to: validRegistrationPayload.email,
              from: 'accounts@distnode.com'
            })

            emailVerificationTokenModel
              .exists({
                user_id: user._id.toString()
              })
              .then((exists) => {
                chai.expect(exists).not.to.be.null
                done()
              })
              .catch((err) => {
                done(err)
              })
          })
      })
    })

    it('should return 400 if email has already been verified', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then((user) => {
          chai
            .request(app)
            .post('/auth/resend-verification-email')
            .send({ email: user.email })
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(400)
              res.body.should.have.property(
                'resendVerificationError',
                'Email is already verified'
              )

              sinon.assert.notCalled(sendStub)

              emailVerificationTokenModel
                .exists({
                  user_id: user._id.toString()
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

    it('should return 404 if email provided but user not found', (done) => {
      const userID = new mongoose.Types.ObjectId()
      chai
        .request(app)
        .post('/auth/resend-verification-email')
        .send({ email: validRegistrationPayload.email })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(404)
          res.body.should.have.property(
            'resendVerificationError',
            'User not found'
          )

          sinon.assert.notCalled(sendStub)

          emailVerificationTokenModel
            .exists({
              user_id: userID
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

    it('should return 400 if email not provided', (done) => {
      chai
        .request(app)
        .post('/auth/resend-verification-email')
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'resendVerificationError',
            'Email required'
          )
          done()
        })
    })

    it('should delete previous verification token if multiple are requested', (done) => {
      userModel.create(validRegistrationPayload).then((user) => {
        chai
          .request(app)
          .post('/auth/resend-verification-email')
          .send({ email: user.email })
          .end((err, res1) => {
            if (err) {
              done(err)
            }
            chai
              .request(app)
              .post('/auth/resend-verification-email')
              .send({ email: user.email })
              .end((err, res2) => {
                if (err) {
                  done(err)
                }
                res1.should.have.status(200)
                res2.should.have.status(200)
                res1.body.should.have.property(
                  'resendVerificationSuccess',
                  'New verification email sent successfully'
                )
                res2.body.should.have.property(
                  'resendVerificationSuccess',
                  'New verification email sent successfully'
                )

                sinon.assert.callCount(sendStub, 2)

                sinon.assert.calledWithMatch(sendStub, {
                  to: validRegistrationPayload.email,
                  from: 'accounts@distnode.com'
                })

                emailVerificationTokenModel
                  .find({
                    user_id: user._id.toString()
                  })
                  .then((exists) => {
                    chai.expect(exists.length).to.equal(1)
                    done()
                  })
                  .catch((err) => {
                    done(err)
                  })
              })
          })
      })
    })
  })

  describe('POST /auth/verify-email', () => {
    afterEach(async function () {
      await userModel.deleteMany()
      await emailVerificationTokenModel.deleteMany()
    })

    it('should return 200 if valid verification token provided and user updated', (done) => {
      userModel.create(validRegistrationPayload).then((user) => {
        emailVerificationTokenModel
          .create({
            user_id: user._id
          })
          .then((token) => {
            chai.expect(token).not.to.be.null
            chai
              .request(app)
              .post(`/auth/verify-email?token=${token.token}`)
              .end((err, res) => {
                if (err) {
                  done(err)
                }
                res.should.have.status(200)
                res.body.should.have.property(
                  'verifyEmailSuccess',
                  'Email verified successfully'
                )

                userModel
                  .findOne({
                    user_id: token.user_id
                  })
                  .then((updatedUser) => {
                    chai.expect(updatedUser.emailVerified).to.be.true
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
    })

    it('should return 404 if valid verification token provided but user not found', (done) => {
      const userID = new mongoose.Types.ObjectId()
      emailVerificationTokenModel
        .create({
          user_id: userID
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .post(`/auth/verify-email?token=${token.token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(404)
              res.body.should.have.property(
                'verifyEmailError',
                'User not found'
              )
              done()
            })
        })
        .catch((err) => {
          done(err)
        })
    })

    it('should return 400 if non-existent verification token provided', (done) => {
      const verificationTokenID = new mongoose.Types.ObjectId()
      chai
        .request(app)
        .post(`/auth/verify-email?token=${verificationTokenID}`)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'verifyEmailError',
            'Invalid verification token'
          )
          done()
        })
    })

    it('should return 400 if no token provided', (done) => {
      chai
        .request(app)
        .post('/auth/verify-email')
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'verifyEmailError',
            'Verification token required'
          )
          done()
        })
    })

    it('should return 400 if email has already been verified', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then((user) => {
          emailVerificationTokenModel
            .create({
              user_id: user._id
            })
            .then((token) => {
              chai.expect(token).not.to.be.null
              chai
                .request(app)
                .post(`/auth/verify-email?token=${token.token}`)
                .end((err, res) => {
                  if (err) {
                    done(err)
                  }
                  res.should.have.status(400)
                  res.body.should.have.property(
                    'verifyEmailError',
                    'Email is already verified'
                  )
                  done()
                })
            })
            .catch((err) => {
              done(err)
            })
        })
    })
  })

  describe('GET /auth/password-reset', () => {
    let sendStub: sinon.SinonStub

    beforeEach(() => {
      sendStub = sinon.stub(sgMail, 'send')
    })

    afterEach(async function () {
      await userModel.deleteMany()
      await passwordResetTokenModel.deleteMany()
      sendStub.restore()
    })

    it('should return 200 if valid email address provided and email sent', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then((user) => {
          chai.expect(user).not.to.be.null
          chai
            .request(app)
            .get(`/auth/password-reset?email=${user.email}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(200)
              res.body.should.have.property(
                'passwordResetSuccess',
                'Password reset email sent successfully'
              )

              sinon.assert.calledWithMatch(sendStub, {
                to: validRegistrationPayload.email,
                from: 'accounts@distnode.com'
              })

              passwordResetTokenModel
                .exists({
                  user_id: user._id.toString()
                })
                .then((exists) => {
                  chai.expect(exists).not.to.be.null
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

    it('should return 400 if email has not been verified', (done) => {
      userModel
        .create(validRegistrationPayload)
        .then((user) => {
          chai.expect(user).not.to.be.null
          chai
            .request(app)
            .get(`/auth/password-reset?email=${user.email}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(400)
              res.body.should.have.property(
                'passwordResetError',
                'Email must be verified before resetting password'
              )

              sinon.assert.notCalled(sendStub)

              passwordResetTokenModel
                .exists({
                  user_id: user._id.toString()
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

    it('should return 404 if user with provided email not found', (done) => {
      chai
        .request(app)
        .get('/auth/password-reset?email=non-existent-email@distnode.com')
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(404)
          res.body.should.have.property('passwordResetError', 'User not found')

          sinon.assert.notCalled(sendStub)

          passwordResetTokenModel
            .find({})
            .then((exists) => {
              chai.expect(exists.length).to.equal(0)
              done()
            })
            .catch((err) => {
              done(err)
            })
        })
    })

    it('should return 400 if email not provided', (done) => {
      chai
        .request(app)
        .get('/auth/password-reset')
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'passwordResetError',
            'Email is required for password reset'
          )
          done()
        })
    })

    it('should delete previous reset token if multiple are requested', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then((user) => {
          chai.expect(user).not.to.be.null
          chai
            .request(app)
            .get(`/auth/password-reset?email=${user.email}`)
            .end((err, res1) => {
              if (err) {
                done(err)
              }
              chai
                .request(app)
                .get(`/auth/password-reset?email=${user.email}`)
                .end((err, res2) => {
                  if (err) {
                    done(err)
                  }
                  res1.should.have.status(200)
                  res2.should.have.status(200)
                  res1.body.should.have.property(
                    'passwordResetSuccess',
                    'Password reset email sent successfully'
                  )
                  res2.body.should.have.property(
                    'passwordResetSuccess',
                    'Password reset email sent successfully'
                  )

                  sinon.assert.callCount(sendStub, 2)

                  sinon.assert.calledWithMatch(sendStub, {
                    to: validRegistrationPayload.email,
                    from: 'accounts@distnode.com'
                  })

                  passwordResetTokenModel
                    .find({
                      user_id: user._id.toString()
                    })
                    .then((exists) => {
                      chai.expect(exists.length).to.equal(1)
                      done()
                    })
                    .catch((err) => {
                      done(err)
                    })
                })
            })
        })
        .catch((err) => {
          done(err)
        })
    })
  })

  describe('POST /auth/password-reset', () => {
    afterEach(async function () {
      await userModel.deleteMany()
      await passwordResetTokenModel.deleteMany()
      await refreshTokenModel.deleteMany()
    })

    it('should return 200, update user, and delete refresh tokens for user if valid input provided', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then((user) => {
          passwordResetTokenModel
            .create({
              user_id: user._id
            })
            .then((token) => {
              chai.expect(token).not.to.be.null
              chai
                .request(app)
                .post(`/auth/password-reset?token=${token.token}`)
                .send({ password: `New${validRegistrationPayload.password}` })
                .end((err, res) => {
                  if (err) {
                    done(err)
                  }
                  res.should.have.status(200)
                  res.body.should.have.property(
                    'passwordResetSuccess',
                    'Password reset successfully'
                  )

                  userModel
                    .findOne({
                      user_id: token.user_id
                    })
                    .then((updatedUser) => {
                      chai
                        .expect(user.password)
                        .not.to.equal(updatedUser.password)

                      refreshTokenModel
                        .find({
                          user_id: token.user_id
                        })
                        .then((refreshTokens) => {
                          chai.expect(refreshTokens.length).to.equal(0)
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
        })
    })

    it('should return 404 if valid reset token and password provided but user not found', (done) => {
      const userID = new mongoose.Types.ObjectId()
      passwordResetTokenModel
        .create({
          user_id: userID
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .post(`/auth/password-reset?token=${token.token}`)
            .send({ password: `New${validRegistrationPayload.password}` })
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(404)
              res.body.should.have.property(
                'passwordResetError',
                'User not found'
              )
              done()
            })
        })
        .catch((err) => {
          done(err)
        })
    })

    it('should return 400 if non-existent reset token provided', (done) => {
      const passwordResetTokenID = new mongoose.Types.ObjectId()
      chai
        .request(app)
        .post(`/auth/password-reset?token=${passwordResetTokenID}`)
        .send({ password: `New${validRegistrationPayload.password}` })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'passwordResetError',
            'Invalid password reset token'
          )
          done()
        })
    })

    it('should return 400 if no password reset token provided', (done) => {
      chai
        .request(app)
        .post('/auth/password-reset')
        .send({ password: `New${validRegistrationPayload.password}` })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'passwordResetError',
            'Password reset token required'
          )
          done()
        })
    })

    it('should return 400 if no new password provided', (done) => {
      const passwordResetTokenID = new mongoose.Types.ObjectId()
      chai
        .request(app)
        .post(`/auth/password-reset?token=${passwordResetTokenID}`)
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'passwordResetError',
            'New password required'
          )
          done()
        })
    })

    it('should return 400 if new password does not meet requirements', (done) => {
      const passwordResetTokenID = new mongoose.Types.ObjectId()
      chai
        .request(app)
        .post(`/auth/password-reset?token=${passwordResetTokenID}`)
        .send({ password: `invalid` })
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(400)
          res.body.should.have.property(
            'passwordResetError',
            'New password does not meet requirements'
          )
          done()
        })
    })
  })

  describe('POST /auth/login', () => {
    afterEach(async function () {
      await userModel.deleteMany()
    })

    it('should return 200 and set token cookies for valid login', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then(() => {
          chai
            .request(app)
            .post('/auth/login')
            .send(validRegistrationPayload)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              console.log('DEBUG:', res.body)
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
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then(() => {
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

  describe('GET /auth/refreshed-tokens', () => {
    afterEach(async function () {
      await userModel.deleteMany()
    })

    it('should return 200 and set token cookies for valid refresh', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then(() => {
          const agent = chai.request.agent(app)

          agent
            .post('/auth/login')
            .send(validRegistrationPayload)
            .then((loginRes) => {
              loginRes.should.have.cookie('accessToken')
              loginRes.should.have.cookie('refreshToken')
              loginRes.should.have.cookie('csrfToken')

              return agent.get('/auth/refreshed-tokens').then((refreshRes) => {
                refreshRes.should.have.status(200)
                refreshRes.should.have.cookie('accessToken')
                refreshRes.should.have.cookie('csrfToken')
                refreshRes.body.should.have.property(
                  'refreshSuccess',
                  'Tokens refreshed successfully'
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
        .get('/auth/refreshed-tokens')
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
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then(() => {
          const agent = chai.request.agent(app)

          agent
            .get('/auth/refreshed-tokens')
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

  describe('GET /auth/refresh-token/current', () => {
    afterEach(async function () {
      await refreshTokenModel.deleteMany()
    })

    it('should return 200 if valid refresh token provided and found', (done) => {
      refreshTokenModel
        .create({
          token: 'token',
          user_id: new mongoose.Types.ObjectId()
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .get('/auth/refresh-token/current')
            .set('Cookie', `refreshToken=${token.token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(200)
              res.body.should.have.property(
                'getRefreshIDSuccess',
                'Refresh token ID obtained successfully'
              )
              res.body.should.have.property('refreshID', token._id.toString())
              done()
            })
        })
        .catch((err) => {
          done(err)
        })
    })

    it('should return 404 if refresh token not found', (done) => {
      chai
        .request(app)
        .get('/auth/refresh-token/current')
        .set('Cookie', 'refreshToken=non-existent-token')
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(404)
          res.body.should.have.property(
            'getRefreshIDError',
            'Refresh token not found'
          )
          done()
        })
    })

    it('should return 401 if refresh token not provided', (done) => {
      chai
        .request(app)
        .get('/auth/refresh-token/current')
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property(
            'getRefreshIDError',
            'Refresh token cookie required'
          )
          done()
        })
    })
  })

  describe('GET /auth/refresh-token/all', () => {
    afterEach(async function () {
      await refreshTokenModel.deleteMany()
    })

    it('should return 200 if valid refresh token provided and found', (done) => {
      const userID = new mongoose.Types.ObjectId()
      refreshTokenModel
        .insertMany([
          { token: 'token1', user_id: userID },
          { token: 'token2', user_id: userID }
        ])
        .then((tokens) => {
          chai.expect(tokens).not.to.be.null
          chai
            .request(app)
            .get('/auth/refresh-token/all')
            .set('Cookie', `refreshToken=${tokens[0].token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(200)
              res.body.should.have.property(
                'getRefreshIDSuccess',
                'Refresh token IDs obtained successfully'
              )
              chai
                .expect(res.body.refreshIDs)
                .to.have.members(tokens.map((token) => token._id.toString()))
              done()
            })
        })
        .catch((err) => {
          done(err)
        })
    })

    it('should return 404 if refresh token not found', (done) => {
      chai
        .request(app)
        .get('/auth/refresh-token/all')
        .set('Cookie', 'refreshToken=non-existent-token')
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(404)
          res.body.should.have.property(
            'getRefreshIDError',
            'Refresh token not found'
          )
          done()
        })
    })

    it('should return 401 if refresh token not provided', (done) => {
      chai
        .request(app)
        .get('/auth/refresh-token/all')
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property(
            'getRefreshIDError',
            'Refresh token cookie required'
          )
          done()
        })
    })
  })

  describe('DELETE /auth/refresh-token/id/:refreshID', () => {
    afterEach(async function () {
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
            .delete(`/auth/refresh-token/id/${token._id.toString()}`)
            .set('Cookie', `refreshToken=${token.token}`)
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

    it('should return 400 if passed invalid refresh token', (done) => {
      refreshTokenModel
        .create({
          token: 'token',
          user_id: new mongoose.Types.ObjectId()
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .delete('/auth/refresh-token/id/invalid-token')
            .set('Cookie', `refreshToken=${token.token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(400)
              res.body.should.have.property(
                'deleteRefreshError',
                'Invalid refresh token ID param'
              )

              refreshTokenModel
                .exists({
                  token: token.token
                })
                .then((exists) => {
                  chai.expect(exists).not.to.be.null
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

    it('should return 404 if passed refresh token not found', (done) => {
      refreshTokenModel
        .create({
          token: 'token',
          user_id: new mongoose.Types.ObjectId()
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .delete('/auth/refresh-token/id/622ced040b71e931094f9bcc')
            .set('Cookie', `refreshToken=${token.token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(404)
              res.body.should.have.property(
                'deleteRefreshError',
                'Refresh token not found'
              )

              refreshTokenModel
                .exists({
                  token: token.token
                })
                .then((exists) => {
                  chai.expect(exists).not.to.be.null
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

    it('should return 404 if active refresh token not found', (done) => {
      refreshTokenModel
        .create({
          token: 'token',
          user_id: new mongoose.Types.ObjectId()
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .delete(`/auth/refresh-token/id/${token._id.toString()}`)
            .set('Cookie', `refreshToken=non-existent-token`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(404)
              res.body.should.have.property(
                'deleteRefreshError',
                'Refresh token not found'
              )

              refreshTokenModel
                .exists({
                  token: token.token
                })
                .then((exists) => {
                  chai.expect(exists).not.to.be.null
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

    it('should return 401 if active refresh token not provided', (done) => {
      refreshTokenModel
        .create({
          token: 'token',
          user_id: new mongoose.Types.ObjectId()
        })
        .then((token) => {
          chai.expect(token).not.to.be.null
          chai
            .request(app)
            .delete(`/auth/refresh-token/id/${token.token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(401)
              res.body.should.have.property(
                'deleteRefreshError',
                'Refresh token cookie required'
              )

              refreshTokenModel
                .exists({
                  token: token.token
                })
                .then((exists) => {
                  chai.expect(exists).not.to.be.null
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

    it('should return 401 if active and passed refresh token users do not match', (done) => {
      refreshTokenModel
        .insertMany([
          { token: 'token1', user_id: new mongoose.Types.ObjectId() },
          { token: 'token2', user_id: new mongoose.Types.ObjectId() }
        ])
        .then((tokens) => {
          chai.expect(tokens).not.to.be.null
          chai
            .request(app)
            .delete(`/auth/refresh-token/id/${tokens[0]._id.toString()}`)
            .set('Cookie', `refreshToken=${tokens[1].token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(401)
              res.body.should.have.property(
                'deleteRefreshError',
                'Invalid refresh token'
              )

              refreshTokenModel
                .find({
                  _id: { $in: tokens.map((token) => token._id) }
                })
                .then((find) => {
                  const foundIDs = find.map((token) => token._id.toString())
                  const expectedIDs = tokens.map((token) =>
                    token._id.toString()
                  )
                  chai.expect(foundIDs).to.have.members(expectedIDs)
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
  })

  describe('DELETE /auth/refresh-token/current', () => {
    afterEach(async function () {
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
            .delete('/auth/refresh-token/current')
            .set('Cookie', `refreshToken=${token.token}`)
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
        .delete('/auth/refresh-token/current')
        .set('Cookie', 'refreshToken=non-existent-token')
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

    it('should return 401 if refresh token not provided', (done) => {
      chai
        .request(app)
        .delete('/auth/refresh-token/current')
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property(
            'deleteRefreshError',
            'Refresh token cookie required'
          )
          done()
        })
    })
  })

  describe('DELETE /auth/refresh-token/all', () => {
    afterEach(async function () {
      await refreshTokenModel.deleteMany()
    })

    it('should return 200 if valid refresh token provided and deleted', (done) => {
      const userID = new mongoose.Types.ObjectId()
      refreshTokenModel
        .insertMany([
          { token: 'token1', user_id: userID },
          { token: 'token2', user_id: userID }
        ])
        .then((tokens) => {
          chai.expect(tokens).not.to.be.null
          chai
            .request(app)
            .delete('/auth/refresh-token/all')
            .set('Cookie', `refreshToken=${tokens[0].token}`)
            .end((err, res) => {
              if (err) {
                done(err)
              }
              res.should.have.status(200)
              res.body.should.have.property(
                'deleteRefreshSuccess',
                'Refresh tokens deleted successfully'
              )

              refreshTokenModel
                .exists({
                  user_id: userID
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
        .delete('/auth/refresh-token/all')
        .set('Cookie', 'refreshToken=non-existent-token')
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

    it('should return 401 if refresh token not provided', (done) => {
      chai
        .request(app)
        .delete('/auth/refresh-token/all')
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }
          res.should.have.status(401)
          res.body.should.have.property(
            'deleteRefreshError',
            'Refresh token cookie required'
          )
          done()
        })
    })
  })

  describe('DELETE /auth/user', () => {
    afterEach(async function () {
      await userModel.deleteMany()
      await refreshTokenModel.deleteMany()
    })

    it('should return 200 and delete user and refresh tokens if they exist', (done) => {
      userModel
        .create({
          ...validRegistrationPayload,
          emailVerified: true
        })
        .then((user) => {
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
                .delete('/auth/user')
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
        .delete('/auth/user')
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
        .delete('/auth/user')
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
        .delete('/auth/user')
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
        .delete('/auth/user')
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
        .delete('/auth/user')
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
        .delete('/auth/user')
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
        .delete('/auth/user')
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
