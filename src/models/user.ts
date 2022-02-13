// Third party
import argon2 from 'argon2'
import { NextFunction } from 'express'
import mongoose from 'mongoose'

// Configurations
import { ARGON_MEMORY_COST } from '../config'

const argon2Options = {
    type: argon2.argon2id,
    memoryCost: ARGON_MEMORY_COST
}

const hashPassword = async (password: string): Promise<string> => {
    return await argon2.hash(password, argon2Options)
}

const verifyPassword = async (
    hash: string,
    password: string
): Promise<boolean> => {
    return await argon2.verify(hash, password, argon2Options)
}

const userSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
})

userSchema.pre('save', async function (next: NextFunction): Promise<void> {
    if (!this.isModified('password')) return next()

    try {
        this.password = await hashPassword(this.password)
    } catch (err) {
        return next(err)
    }

    next()
})

userSchema.methods.setPassword = async function (
    password: string
): Promise<void> {
    this.password = await hashPassword(password)
}

userSchema.methods.validPassword = async function (
    password: string
): Promise<boolean> {
    return verifyPassword(this.password, password)
}

const userModel = mongoose.model('user', userSchema)

export { userModel, hashPassword, verifyPassword }
