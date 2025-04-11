import { DbSession } from '../db';
import { AuthenticatedUser } from '../models/user-model';
import { StatusCodes } from 'http-status-codes';
import argon2 from '@node-rs/argon2';
import { Utils, BaseResponse } from './utils';
import { JwtUtils } from './jwt-utils';

export type UserResponse = BaseResponse<AuthenticatedUser>;

const passwordOptions = {
    memoryCost: 2 ** 16,
    timeCost: 4,
    outputLen: 32,
    parallelism: 2,
    algorithm: argon2.Algorithm.Argon2id,
};

export class UserUtils extends Utils {
    /**
     * Hashes a password using Argon2
     * @param password The plain text password to hash
     * @returns The hashed password
     */
    public async hashPassword(password: string): Promise<string> {
        try {
            return await argon2.hash(password, passwordOptions);
        } catch (error) {
            console.error('Password hashing error:', error);
            throw new Error(`Error hashing password: ${error}`);
        }
    }

    /**
     * Verifies a password against a hash
     * @param hashed The hashed password
     * @param password The plain text password to verify
     * @returns True if the password matches the hash, false otherwise
     */
    public async verifyPassword(hashed: string, password: string): Promise<boolean> {
        try {
            return await argon2.verify(hashed, password, passwordOptions);
        } catch (error) {
            console.error('Password verification error:', error);
            throw new Error(`Error verifying password: ${error}`);
        }
    }

    /**
     * Creates a new user
     * @param username The username for the new user
     * @param password The password for the new user
     * @returns A UserResponse object containing statusCode, data, and optional error message
     */
    public async createUser(username: string, password: string): Promise<UserResponse> {
        if (!this.isValidString(username, 3, 20, /^[a-zA-Z0-9_]+$/)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Username must be valid string between 3 and 20 characters and can only contain letters, numbers, and underscores'
            );
        }

        if (!this.isValidString(password)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Password must be valid string'
            );
        }

        const existingUser = await this.dbSession.query(
            `SELECT username FROM account WHERE username = $1`,
            [username]
        );

        if ((existingUser.rowCount ?? 0) > 0) {
            return this.createErrorResponse(
                StatusCodes.CONFLICT,
                'Username already exists'
            );
        }

        const hashedPassword = await this.hashPassword(password);
        const result = await this.dbSession.query(`
            INSERT INTO account (username, password_hash)
            VALUES ($1, $2) 
            RETURNING uid, username, created_at`,
            [username, hashedPassword]
        );

        if (result.rowCount === 0) {
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'Failed to create user'
            );
        }

        const user: AuthenticatedUser = result.rows[0];
        return this.createSuccessResponse(user, StatusCodes.CREATED);
    }

    /**
     * Gets a user by their ID
     * @param uid The user ID to lookup
     * @returns A UserResponse object containing statusCode, data, and optional error message
     */
    public async getUserById(uid: number): Promise<UserResponse> {
        if (!this.isValidUserId(uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid user ID'
            );
        }

        const result = await this.dbSession.query(`
            SELECT uid, username, created_at 
            FROM account 
            WHERE uid = $1`,
            [uid]
        );

        if (result.rowCount === 0) {
            return this.createErrorResponse(
                StatusCodes.NOT_FOUND,
                'User not found'
            );
        }

        const user: AuthenticatedUser = result.rows[0];
        return this.createSuccessResponse(user);
    }

    /**
     * Login a user and generate JWT token
     * @param username The username for login
     * @param password The password to verify
     * @returns A UserResponse object containing statusCode, data, and optional error message
     */
    public async loginUser(username: string, password: string): Promise<UserResponse> {
        if (!this.isValidString(username) || !this.isValidString(password)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Username and password are required'
            );
        }

        const result = await this.dbSession.query(`
        SELECT uid, username, password_hash, created_at 
        FROM account 
        WHERE username = $1`,
            [username]
        );

        if (result.rowCount === 0) {
            return this.createErrorResponse(
                StatusCodes.UNAUTHORIZED,
                'Invalid username or password'
            );
        }

        const user = result.rows[0];
        const passwordValid = await this.verifyPassword(user.password_hash, password);

        if (!passwordValid) {
            return this.createErrorResponse(
                StatusCodes.UNAUTHORIZED,
                'Invalid username or password'
            );
        }

        const token = JwtUtils.generateToken({
            uid: user.uid,
            username: user.username
        });

        const userData: AuthenticatedUser = {
            uid: user.uid,
            username: user.username,
            created_at: user.created_at,
            token: token
        };

        return this.createSuccessResponse(userData);
    }

    /**
     * Deletes a user account by their ID
     * @param uid The user ID to delete
     * @returns A BaseResponse object containing statusCode and optional error message
     */
    public async deleteUser(uid: number): Promise<BaseResponse<null>> {
        if (!this.isValidUserId(uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid user ID'
            );
        }

        const userExists = await this.dbSession.query(
            `SELECT uid FROM account WHERE uid = $1`,
            [uid]
        );

        if (userExists.rowCount === 0) {
            return this.createErrorResponse(
                StatusCodes.NOT_FOUND,
                'User not found'
            );
        }

        await this.dbSession.query(
            `DELETE FROM contact WHERE user_id = $1 OR contact_user_id = $1`,
            [uid]
        );

        await this.dbSession.query(
            `DELETE FROM message WHERE sender_uid = $1 OR receiver_uid = $1`,
            [uid]
        );

        const result = await this.dbSession.query(
            `DELETE FROM account WHERE uid = $1`,
            [uid]
        );

        if (result.rowCount === 0) {
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'Failed to delete user'
            );
        }

        return this.createSuccessResponse(null);
    }
}
