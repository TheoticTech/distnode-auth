// Third party
import assert from 'assert'

// Local
import { hashPassword, verifyPassword } from '../src/models/user'

describe('User model', function () {
    describe('hashPassword()', function () {
        it('should return a string', async function () {
            const hashedPassword = await hashPassword('password')
            assert.equal(typeof hashedPassword, 'string')
        })
    })

    describe('verifyPassword()', function () {
        it('should return true when given correct password', async function () {
            const hashedPassword = await hashPassword('password')
            const verification = await verifyPassword(
                hashedPassword,
                'password'
            )
            assert(verification)
        })

        it('should return false when given incorrect password', async function () {
            const hashedPassword = await hashPassword('password')
            const verification = await verifyPassword(
                hashedPassword,
                'notPassword'
            )
            assert(!verification)
        })
    })
})
