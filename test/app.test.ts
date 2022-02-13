// Third party
import chai from 'chai'
import chaiHttp from 'chai-http'

// Local
import { app } from '../src/app'
import { userModel } from '../src/models/user'

chai.use(chaiHttp)
chai.should()

// NOTE: App requires a MongoDB connection
describe('Authentication routes', function () {

    describe('POST /register', function () {

        beforeEach(async function () {
            await userModel.deleteMany()
        })

        const validRegistrationPayload = {
            firstName: 'John',
            lastName: 'Doe',
            username: 'johndoe',
            email: 'johndoe@distnode.com',
            password: 'P@ssw0rd'
        }

        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { password, ...missingPasswordPayload } =
            validRegistrationPayload

        it('should return 201 and token when supplied proper input', (done) => {
            chai.request(app)
                .post('/auth/register')
                .send(validRegistrationPayload)
                .end((err, res) => {
                    res.should.have.status(201)
                    res.body.should.have.property('token')
                    done()
                })
        })

        it('should return 400 if any registration fields are missing', (done) => {
            chai.request(app)
                .post('/auth/register')
                .send(missingPasswordPayload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
                    done()
                })
        })

        it('should return 400 if password is too short', (done) => {
            const payload = {
                ...missingPasswordPayload,
                password: 'P@ssw0r'
            }
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
                    done()
                })
        })

        it('should return 400 if password is too long', (done) => {
            const payload = {
                ...missingPasswordPayload,
                password: 'P@ssw0rd'.repeat(10)
            }
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
                    done()
                })
        })

        it('should return 400 if password is missing a number', (done) => {
            const payload = {
                ...missingPasswordPayload,
                password: 'P@ssword'
            }
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
                    done()
                })
        })

        it('should return 400 if password is missing a lowercase letter', (done) => {
            const payload = {
                ...missingPasswordPayload,
                password: 'PASSW0RD'
            }
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
                    done()
                })
        })

        it('should return 400 if password is missing an uppercase letter', (done) => {
            const payload = {
                ...missingPasswordPayload,
                password: 'p@ssw0rd'
            }
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
                    done()
                })
        })

        it('should return 400 if password is missing a special character', (done) => {
            const payload = {
                ...missingPasswordPayload,
                password: 'Passw0rd'
            }
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
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
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
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
            chai.request(app)
                .post('/auth/register')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.be.a('object')
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
                chai.request(app)
                    .post('/auth/register')
                    .send(secondPayload)
                    .end((err, res) => {
                        res.should.have.status(409)
                        res.body.should.be.a('object')
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
                chai.request(app)
                    .post('/auth/register')
                    .send(secondPayload)
                    .end((err, res) => {
                        res.should.have.status(409)
                        res.body.should.be.a('object')
                        done()
                    })
            })
        })
    })

    describe('POST /auth/login', () => {

        beforeEach(async function () {
            await userModel.deleteMany()
        })

        const validRegistrationPayload = {
            firstName: 'John',
            lastName: 'Doe',
            username: 'johndoe',
            email: 'johndoe@distnode.com',
            password: 'P@ssw0rd'
        }

        it('should return 200 and token for valid login', (done) => {
            userModel.create(validRegistrationPayload).then(() => {
                chai.request(app)
                    .post('/auth/login')
                    .send(validRegistrationPayload)
                    .end((err, res) => {
                        res.should.have.status(200)
                        res.body.should.have.property('token')
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
                chai.request(app)
                    .post('/auth/login')
                    .send(payload)
                    .end((err, res) => {
                        res.should.have.status(401)
                        res.body.should.not.have.property('token')
                        done()
                    })
            })
        })

        it('should return 400 for missing password', (done) => {
            const payload = {
                ...validRegistrationPayload,
                password: undefined
            }
            chai.request(app)
                .post('/auth/login')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.not.have.property('token')
                    done()
                })
        })

        it('should return 400 for missing email', (done) => {
            const payload = {
                ...validRegistrationPayload,
                email: undefined
            }
            chai.request(app)
                .post('/auth/login')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(400)
                    res.body.should.not.have.property('token')
                    done()
                })
        })

        it('should return 401 for non-existent user', (done) => {
            const payload = {
                ...validRegistrationPayload,
                email: 'nonexistent@distnode.com'
            }
            chai.request(app)
                .post('/auth/login')
                .send(payload)
                .end((err, res) => {
                    res.should.have.status(401)
                    res.body.should.not.have.property('token')
                    done()
                })
        })

    })
})
