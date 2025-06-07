import { AuthenticatedUser, User } from '../models/user-model';
import { StatusCodes } from 'http-status-codes';
import argon2 from '@node-rs/argon2';
import { Utils, BaseResponse } from './utils';
import { ContactUtils } from './contact-utils';

export type UserResponse = BaseResponse<AuthenticatedUser>;
export type BasicUserResponse = BaseResponse<User>;

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
     * @param displayName Optional display name for the user
     * @param shadowMode Optional flag to set shadow mode (defaults to false)
     * @param fullNameSearch Optional flag to set full name search requirement (defaults to false)
     * @returns A UserResponse object containing statusCode, data, and optional error message
     */
    public async createUser(
        username: string,
        password: string,
        publicKey: string,
        displayName?: string,
        shadowMode: boolean | string = false,
        fullNameSearch: boolean | string = false
    ): Promise<UserResponse> {
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

        if (shadowMode !== undefined && !this.isValidBoolean(shadowMode)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Shadow mode must be a boolean value'
            );
        }

        if (fullNameSearch !== undefined && !this.isValidBoolean(fullNameSearch)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Full name search must be a boolean value'
            );
        }

        const shadowModeValue = typeof shadowMode === 'string'
            ? shadowMode.toLowerCase() === 'true'
            : Boolean(shadowMode);

        const fullNameSearchValue = typeof fullNameSearch === 'string'
            ? fullNameSearch.toLowerCase() === 'true'
            : Boolean(fullNameSearch);

        try {
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
            INSERT INTO account (
                username, 
                password_hash,
                display_name,
                shadow_mode,
                full_name_search,
                public_key
            )
            VALUES ($1, $2, $3, $4, $5, $6) 
            RETURNING
                uid,
                username,
                created_at,
                display_name,
                is_deleted,
                shadow_mode,
                full_name_search,
                public_key
            `,
                [
                    username,
                    hashedPassword,
                    displayName || null,
                    shadowModeValue,
                    fullNameSearchValue,
                    publicKey
                ]
            );

            if (result.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    'Failed to create user'
                );
            }

            const user: AuthenticatedUser = {
                uid: result.rows[0].uid,
                username: result.rows[0].username,
                created_at: result.rows[0].created_at,
                display_name: result.rows[0].display_name,
                is_deleted: result.rows[0].is_deleted,
                shadow_mode: result.rows[0].shadow_mode,
                full_name_search: result.rows[0].full_name_search,
                public_key: result.rows[0].public_key
            };

            return this.createSuccessResponse(user, StatusCodes.CREATED);
        } catch (error) {
            console.error('Error creating user:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An unexpected error occurred while creating the user.'
            );
        }
    }

    /**
     * Gets a user by their ID
     * @param uid The user ID to lookup
     * @param requestingUserId The ID of the user making the request
     * @returns A BasicUserResponse object containing statusCode, data, and optional error message
     */
    public async getUserById(uid: number, requestingUserId: number): Promise<BasicUserResponse> {
        if (!this.isValidUserId(uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid user ID'
            );
        }

        if (!this.isValidUserId(requestingUserId)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid requesting user ID'
            );
        }

        try {
            const result = await this.dbSession.query(`
                SELECT uid, username, created_at, display_name, is_deleted, shadow_mode, full_name_search, public_key
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

            const user = result.rows[0];

            if (uid === requestingUserId) {
                return this.createSuccessResponse({
                    uid: user.uid,
                    username: user.username,
                    display_name: user.display_name,
                    created_at: user.created_at,
                    public_key: user.public_key
                });
            }

            if (user.shadow_mode || user.full_name_search) {
                const hasContact = await this.hasContactWith(requestingUserId, uid);

                if (!hasContact) {
                    return this.createErrorResponse(
                        StatusCodes.FORBIDDEN,
                        'You do not have permission to view this user profile'
                    );
                }
            }

            const userData: User = {
                uid: user.uid,
                username: user.username,
                display_name: user.display_name,
                created_at: user.created_at,
                public_key: user.public_key

            };

            return this.createSuccessResponse(userData);
        } catch (error) {
            console.error('Error getting user by ID:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An unexpected error occurred while retrieving the user.'
            );
        }
    }

    /**
     * Login a user
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

        try {
            const result = await this.dbSession.query(`
                SELECT
                    uid,
                    username,
                    password_hash,
                    created_at,
                    display_name,
                    is_deleted,
                    shadow_mode,
                    full_name_search,
                    public_key
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

            const userData: AuthenticatedUser = {
                uid: user.uid,
                username: user.username,
                created_at: user.created_at,
                display_name: user.display_name,
                is_deleted: user.is_deleted,
                shadow_mode: user.shadow_mode,
                full_name_search: user.full_name_search,
                public_key: user.public_key
            };

            return this.createSuccessResponse(userData);
        } catch (error) {
            console.error('Error logging in user:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An unexpected error occurred during login.'
            );
        }
    }

    /**
     * Soft deletes a user account by scrubbing their data and marking them as deleted
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

        const userExists = await this.userExists(uid);
        if (!userExists) {
            return this.createErrorResponse(
                StatusCodes.NOT_FOUND,
                'User not found'
            );
        }

        try {
            const randomString = Math.random().toString(36).substring(2, 10);
            const deletedUsername = `Deleted User #${randomString}`;

            const impossibleHash = '$argon2id$v=99$IMPOSSIBLE-HASH-NOT-VALID$' + randomString;

            const result = await this.dbSession.query(`
            UPDATE account 
            SET is_deleted = TRUE,
                username = $2,
                display_name = NULL,
                password_hash = $3,
                created_at = TO_TIMESTAMP(0),
                shadow_mode = FALSE,
                full_name_search = FALSE,
                public_key = NULL
            WHERE uid = $1`,
                [uid, deletedUsername, impossibleHash]
            );

            if (result.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    'Failed to delete user'
                );
            }

            const contactsResult = await this.dbSession.query(`
                SELECT contact_id 
                FROM contact 
                WHERE user_id = $1`,
                [uid]
            );

            const contactUtils = new ContactUtils(this.dbSession);

            for (const row of contactsResult.rows) {
                await contactUtils.deleteContactViaContactId(row.contact_id);
            }

            return this.createSuccessResponse(null);
        } catch (error) {
            console.error('Error deleting user:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An unexpected error occurred while deleting the user.'
            );
        }
    }

    /**
     * Updates a user's information including username, display name, and privacy settings
     * @param uid The user ID to update
     * @param options Update options including username, display name, and privacy settings
     * @returns A UserResponse object containing statusCode, data, and optional error message
     */
    public async updateUser(
        uid: number,
        options: {
            username?: string;
            displayName?: string | null;
            shadowMode?: boolean | string;
            fullNameSearch?: boolean | string;
        }
    ): Promise<UserResponse> {
        if (!this.isValidUserId(uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid user ID'
            );
        }

        const { username, displayName, shadowMode, fullNameSearch } = options;

        try {
            const userQuery = await this.dbSession.query(
                `SELECT uid, is_deleted FROM account WHERE uid = $1`,
                [uid]
            );

            if (userQuery.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.NOT_FOUND,
                    'User not found'
                );
            }

            if (userQuery.rows[0].is_deleted) {
                return this.createErrorResponse(
                    StatusCodes.FORBIDDEN,
                    'Cannot update deleted user'
                );
            }

            if (username !== undefined) {
                if (!this.isValidString(username, 3, 20, /^[a-zA-Z0-9_]+$/)) {
                    return this.createErrorResponse(
                        StatusCodes.BAD_REQUEST,
                        'Username must be valid string between 3 and 20 characters and can only contain letters, numbers, and underscores'
                    );
                }

                const existingUser = await this.dbSession.query(
                    `SELECT username FROM account WHERE username = $1 AND uid != $2`,
                    [username, uid]
                );

                if ((existingUser.rowCount ?? 0) > 0) {
                    return this.createErrorResponse(
                        StatusCodes.CONFLICT,
                        'Username already exists'
                    );
                }
            }

            if (displayName !== undefined && displayName !== null && displayName !== '' && !this.isValidString(displayName, 0, 100)) {
                return this.createErrorResponse(
                    StatusCodes.BAD_REQUEST,
                    'Display name must be a valid string between 1 and 100 characters'
                );
            }

            if (shadowMode !== undefined && !this.isValidBoolean(shadowMode)) {
                return this.createErrorResponse(
                    StatusCodes.BAD_REQUEST,
                    'Shadow mode must be a boolean value'
                );
            }

            if (fullNameSearch !== undefined && !this.isValidBoolean(fullNameSearch)) {
                return this.createErrorResponse(
                    StatusCodes.BAD_REQUEST,
                    'Full name search must be a boolean value'
                );
            }

            const shadowModeValue = shadowMode !== undefined
                ? (typeof shadowMode === 'string'
                    ? shadowMode.toLowerCase() === 'true'
                    : Boolean(shadowMode))
                : undefined;

            const fullNameSearchValue = fullNameSearch !== undefined
                ? (typeof fullNameSearch === 'string'
                    ? fullNameSearch.toLowerCase() === 'true'
                    : Boolean(fullNameSearch))
                : undefined;

            let updateQuery = 'UPDATE account SET';
            const updateParams: any[] = [];
            const updateFields: string[] = [];

            if (username !== undefined) {
                updateParams.push(username);
                updateFields.push(`username = $${updateParams.length}`);
            }

            if (displayName !== undefined) {
                updateParams.push(displayName);
                updateFields.push(`display_name = $${updateParams.length}`);
            }

            if (shadowModeValue !== undefined) {
                updateParams.push(shadowModeValue);
                updateFields.push(`shadow_mode = $${updateParams.length}`);
            }

            if (fullNameSearchValue !== undefined) {
                updateParams.push(fullNameSearchValue);
                updateFields.push(`full_name_search = $${updateParams.length}`);
            }

            if (updateFields.length === 0) {
                return this.createErrorResponse(
                    StatusCodes.BAD_REQUEST,
                    'No valid fields provided for update'
                );
            }

            updateQuery += ` ${updateFields.join(', ')} 
            WHERE uid = $${updateParams.length + 1} 
            RETURNING
                uid,
                username,
                created_at,
                display_name,
                is_deleted,
                shadow_mode,
                full_name_search,
                public_key
            `;
            updateParams.push(uid);

            const result = await this.dbSession.query(updateQuery, updateParams);

            if (result.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    'Failed to update user'
                );
            }

            const user = result.rows[0];

            const userData: AuthenticatedUser = {
                uid: user.uid,
                username: user.username,
                created_at: user.created_at,
                display_name: user.display_name,
                is_deleted: user.is_deleted,
                shadow_mode: user.shadow_mode,
                full_name_search: user.full_name_search,
                public_key: user.public_key
            };

            return this.createSuccessResponse(userData);
        } catch (error) {
            console.error('Error updating user:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An unexpected error occurred while updating the user.'
            );
        }
    }

    /**
     * Updates a user's password after verifying their current password
     * @param uid The user ID to update
     * @param currentPassword The current password to verify
     * @param newPassword The new password to set
     * @returns A UserResponse object containing statusCode, data, and optional error message
     */
    public async updatePassword(
        uid: number,
        currentPassword: string,
        newPassword: string
    ): Promise<UserResponse> {
        if (!this.isValidUserId(uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid user ID'
            );
        }

        if (!this.isValidString(currentPassword) || !this.isValidString(newPassword)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Both current and new password are required'
            );
        }

        try {
            const userQuery = await this.dbSession.query(
                `SELECT
                    uid,
                    username,
                    password_hash,
                    created_at,
                    display_name,
                    is_deleted,
                    shadow_mode,
                    full_name_search,
                    public_key
                FROM account WHERE uid = $1 AND is_deleted = FALSE`,
                [uid]
            );

            if (userQuery.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.NOT_FOUND,
                    'User not found'
                );
            }

            const user = userQuery.rows[0];

            // Verify current password
            const passwordValid = await this.verifyPassword(user.password_hash, currentPassword);

            if (!passwordValid) {
                return this.createErrorResponse(
                    StatusCodes.UNAUTHORIZED,
                    'Current password is incorrect'
                );
            }

            // Hash and set the new password
            const hashedNewPassword = await this.hashPassword(newPassword);

            const updateResult = await this.dbSession.query(
                `UPDATE account SET password_hash = $2 WHERE uid = $1 
                RETURNING uid, username, created_at, display_name, is_deleted, shadow_mode, full_name_search, public_key`,
                [uid, hashedNewPassword]
            );

            if (updateResult.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    'Failed to update password'
                );
            }

            const updatedUser = updateResult.rows[0];

            const userData: AuthenticatedUser = {
                uid: updatedUser.uid,
                username: updatedUser.username,
                created_at: updatedUser.created_at,
                display_name: updatedUser.display_name,
                is_deleted: updatedUser.is_deleted,
                shadow_mode: updatedUser.shadow_mode,
                full_name_search: updatedUser.full_name_search,
                public_key: updatedUser.public_key
            };

            return this.createSuccessResponse(userData);
        } catch (error) {
            console.error('Error updating password:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An unexpected error occurred while updating the password.'
            );
        }
    }

    /**
     * Searches for users based on username query with privacy considerations
     * @param query The search query to find users by username
     * @param limit Maximum number of results to return
     * @returns A BaseResponse containing user search results
     */
    public async searchUsers(query: string, limit: number): Promise<BaseResponse<User[]>> {
        if (!this.isValidString(query)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Search query is required'
            );
        }

        if (!this.isValidId(limit) || limit <= 0 || limit > 100) {
            limit = 20;
        }

        try {
            const searchResults = await this.dbSession.query(`
                SELECT uid, username, display_name, created_at, public_key
                FROM account
                WHERE 
                    (shadow_mode IS NULL OR shadow_mode = false)
                    AND (is_deleted IS NULL OR is_deleted = false)
                    AND (
                        ((full_name_search IS NULL OR full_name_search = false) AND username ILIKE $1)
                        OR
                        (full_name_search = true AND username = $2)
                    )
                ORDER BY username ASC
                LIMIT $3
            `, [`%${query}%`, query, limit]);

            const users: User[] = searchResults.rows.map(row => ({
                uid: row.uid,
                username: row.username,
                display_name: row.display_name,
                created_at: row.created_at,
                public_key: row.public_key
            }));

            return this.createSuccessResponse(users);
        } catch (error) {
            console.error('Error searching for users:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'Failed to search for users'
            );
        }
    }

    /**
     * Updates a user's public key
     * @param uid The user ID to update
     * @param publicKey The new public key
     * @returns A UserResponse object containing statusCode, data, and optional error message
     */
    public async updatePublicKey(uid: number, publicKey: string): Promise<UserResponse> {
        if (!this.isValidUserId(uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid user ID'
            );
        }

        if (!this.isValidString(publicKey)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Valid public key is required'
            );
        }

        try {
            const userQuery = await this.dbSession.query(
                `SELECT uid, is_deleted FROM account WHERE uid = $1`,
                [uid]
            );

            if (userQuery.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.NOT_FOUND,
                    'User not found'
                );
            }

            if (userQuery.rows[0].is_deleted) {
                return this.createErrorResponse(
                    StatusCodes.FORBIDDEN,
                    'Cannot update deleted user'
                );
            }

            const result = await this.dbSession.query(`
                UPDATE account 
                SET public_key = $1
                WHERE uid = $2
                RETURNING
                    uid,
                    username,
                    created_at,
                    display_name,
                    is_deleted,
                    shadow_mode,
                    full_name_search,
                    public_key
            `, [publicKey, uid]);

            if (result.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    'Failed to update public key'
                );
            }

            const user = result.rows[0];

            const userData: AuthenticatedUser = {
                uid: user.uid,
                username: user.username,
                created_at: user.created_at,
                display_name: user.display_name,
                is_deleted: user.is_deleted,
                shadow_mode: user.shadow_mode,
                full_name_search: user.full_name_search,
                public_key: user.public_key
            };

            return this.createSuccessResponse(userData);
        } catch (error) {
            console.error('Error updating public key:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An unexpected error occurred while updating the public key.'
            );
        }
    }

    /**
     * Gets a list of all user public keys
     * @returns A BaseResponse object containing an array of user data with public keys
     */
    public async getAllUsersPublicKeys(): Promise<BaseResponse<{ uid: number; public_key: string }[]>> {
        try {
            const result = await this.dbSession.query(`
                SELECT uid, public_key
                FROM account 
                WHERE is_deleted = false AND public_key IS NOT NULL`
            );

            if (result.rowCount === 0) {
                return this.createSuccessResponse([], StatusCodes.OK);
            }

            return this.createSuccessResponse(result.rows, StatusCodes.OK);
        } catch (error) {
            console.error('Error getting user public keys:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'An error occurred while retrieving user public keys'
            );
        }
    }
}
