import { UserUtils } from '../utilities/user-utils';
import { DbSession } from '../db';
import { StatusCodes } from 'http-status-codes';
import argon2 from '@node-rs/argon2';

jest.mock('@node-rs/argon2');
jest.mock('../utilities/jwt-utils', () => {
    return {
        TokenPayload: {},
        JwtUtils: {
            generateToken: jest.fn((payload) => 'mock-token'),
            verifyToken: jest.fn((token) => {
                return null;
            })
        }
    };
});

jest.mock('jsonwebtoken', () => ({
    sign: jest.fn(),
    verify: jest.fn(),
    TokenExpiredError: class TokenExpiredError extends Error {
        constructor(message: string, expiredAt: Date) {
            super(message);
            this.name = 'TokenExpiredError';
            this.expiredAt = expiredAt;
        }
        expiredAt: Date;
    },
    JsonWebTokenError: class JsonWebTokenError extends Error {
        constructor(message: string) {
            super(message);
            this.name = 'JsonWebTokenError';
        }
    }
}));

process.env.JWT_SECRET = 'test-secret';

describe('UserUtils', () => {
    let dbSessionMock: DbSession;
    let userUtils: UserUtils;

    beforeEach(() => {
        dbSessionMock = {
            query: jest.fn()
        } as unknown as DbSession;

        userUtils = new UserUtils(dbSessionMock);
    });

    describe('hashPassword', () => {
        it('should hash a valid password successfully', async () => {
            (argon2.hash as jest.Mock).mockResolvedValue('hashed-password');
            const result = await userUtils.hashPassword('password123');
            expect(result).toBe('hashed-password');
        });

        it('should throw an error if hashing fails', async () => {
            (argon2.hash as jest.Mock).mockRejectedValue(new Error('Hashing error'));
            await expect(userUtils.hashPassword('password123')).rejects.toThrow('Error hashing password: Error: Hashing error');
        });
    });

    describe('verifyPassword', () => {
        it('should return true for a valid password and hash', async () => {
            (argon2.verify as jest.Mock).mockResolvedValue(true);
            const result = await userUtils.verifyPassword('hashed-password', 'password123');
            expect(result).toBe(true);
        });

        it('should return false for an invalid password and hash', async () => {
            (argon2.verify as jest.Mock).mockResolvedValue(false);
            const result = await userUtils.verifyPassword('hashed-password', 'wrong-password');
            expect(result).toBe(false);
        });

        it('should throw an error if verification fails', async () => {
            (argon2.verify as jest.Mock).mockRejectedValue(new Error('Verification error'));
            await expect(userUtils.verifyPassword('hashed-password', 'password123')).rejects.toThrow('Error verifying password: Error: Verification error');
        });
    });

    describe('createUser', () => {
        it('should return an error response for an invalid username', async () => {
            const result = await userUtils.createUser('ab', 'password123');
            expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
            expect(result.error).toBe('Username must be valid string between 3 and 20 characters and can only contain letters, numbers, and underscores');
        });

        it('should return an error response for an invalid password', async () => {
            const result = await userUtils.createUser('validUsername', '');
            expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
            expect(result.error).toBe('Password must be valid string');
        });

        it('should return an error response if the username already exists', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({ rowCount: 1 });
            const result = await userUtils.createUser('existingUser', 'password123');
            expect(result.statusCode).toBe(StatusCodes.CONFLICT);
            expect(result.error).toBe('Username already exists');
        });

        it('should return an error response if the user creation fails', async () => {
            (dbSessionMock.query as jest.Mock)
                .mockResolvedValueOnce({ rowCount: 0 }) // Check for existing user
                .mockRejectedValue(new Error('Database error')); // Insert new user

            const result = await userUtils.createUser('newUser', 'password123');
            expect(result.statusCode).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
            expect(result.error).toBe('An unexpected error occurred while creating the user.');
        });

        it('should create a new user and return a success response', async () => {
            (dbSessionMock.query as jest.Mock)
                .mockResolvedValueOnce({ rowCount: 0 }) // Check for existing user
                .mockResolvedValueOnce({
                    rowCount: 1,
                    rows: [{ uid: 1, username: 'newUser', created_at: new Date(), display_name: null, is_deleted: false, shadow_mode: false, full_name_search: false }]
                }); // Insert new user


            (argon2.hash as jest.Mock).mockResolvedValue('hashed-password');

            const result = await userUtils.createUser('newUser', 'password123');
            expect(result.statusCode).toBe(StatusCodes.CREATED);
            expect(result.data?.username).toBe('newUser');
        });

        it('should return an error response if the database query fails', async () => {
            (dbSessionMock.query as jest.Mock).mockRejectedValue(new Error('Database error'));
            const result = await userUtils.createUser('newUser', 'password123');
            expect(result.statusCode).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
            expect(result.error).toBe('An unexpected error occurred while creating the user.');
        });
    });

    describe('getUserById', () => {
        it('should return an error response for an invalid user ID', async () => {
            const result = await userUtils.getUserById(-1);
            expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
            expect(result.error).toBe('Invalid user ID');
        });

        it('should return an error response if the user does not exist', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({ rowCount: 0 });
            const result = await userUtils.getUserById(1);
            expect(result.statusCode).toBe(StatusCodes.NOT_FOUND);
            expect(result.error).toBe('User not found');
        });

        it('should return a success response with user data', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({
                rowCount: 1,
                rows: [{ uid: 1, username: 'testUser', created_at: new Date(), display_name: 'Test User', is_deleted: false, shadow_mode: false, full_name_search: false }]
            });
            const result = await userUtils.getUserById(1);
            expect(result.statusCode).toBe(StatusCodes.OK);
            expect(result.data?.username).toBe('testUser');
        });
    });

    describe('loginUser', () => {
        it('should return an error response for invalid username or password', async () => {
            const result = await userUtils.loginUser('', '');
            expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
            expect(result.error).toBe('Username and password are required');
        });

        it('should return an error response for an incorrect password', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({
                rowCount: 1,
                rows: [{ uid: 1, username: 'testUser', password_hash: 'hashed-password' }]
            });
            (argon2.verify as jest.Mock).mockResolvedValue(false);
            const result = await userUtils.loginUser('testUser', 'wrong-password');
            expect(result.statusCode).toBe(StatusCodes.UNAUTHORIZED);
            expect(result.error).toBe('Invalid username or password');
        });

        it('should return a success response with user data and token', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({
                rowCount: 1,
                rows: [{ uid: 1, username: 'testUser', password_hash: 'hashed-password', created_at: new Date() }]
            });
            (argon2.verify as jest.Mock).mockResolvedValue(true);
            const result = await userUtils.loginUser('testUser', 'password123');
            expect(result.statusCode).toBe(StatusCodes.OK);
            expect(result.data?.username).toBe('testUser');
        });
    });

    describe('deleteUser', () => {
        it('should return an error response for an invalid user ID', async () => {
            const result = await userUtils.deleteUser(-1);
            expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
            expect(result.error).toBe('Invalid user ID');
        });

        it('should return an error response if the user does not exist', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({ rowCount: 0 });
            const result = await userUtils.deleteUser(1);
            expect(result.statusCode).toBe(StatusCodes.NOT_FOUND);
            expect(result.error).toBe('User not found');
        });

        it('should return an error response if the user deletion fails', async () => {
            (dbSessionMock.query as jest.Mock)
                .mockResolvedValueOnce({
                    rowCount: 1,
                    rows: [{ uid: 1, username: 'testUser', created_at: new Date(), display_name: 'Test User', is_deleted: false, shadow_mode: false, full_name_search: false }]
                })
                .mockRejectedValue(new Error('Database error'));

            const result = await userUtils.deleteUser(1);
            expect(result.statusCode).toBe(StatusCodes.INTERNAL_SERVER_ERROR);
            expect(result.error).toBe('An unexpected error occurred while deleting the user.');
        });

        it('should return a success response for a valid user ID', async () => {
            (dbSessionMock.query as jest.Mock)
                .mockResolvedValueOnce({
                    rowCount: 1,
                    rows: [{ uid: 1, username: 'testUser', created_at: new Date(), display_name: 'Test User', is_deleted: false, shadow_mode: false, full_name_search: false }]
                }) // user exists
                .mockResolvedValueOnce({ rowCount: 1 }) // Mock for user update query
                .mockResolvedValueOnce({
                    rowCount: 1,
                    rows: [{ contact_id: 123 }]
                }) // Mock for contact deletion query
                .mockResolvedValueOnce({ rowCount: 1 }); // Mock for user deletion query

            const result = await userUtils.deleteUser(1);
            expect(result.statusCode).toBe(StatusCodes.OK);
            expect(result.data).toBe(null);
        });
    });

    describe('updateUser', () => {
        it('should return an error response for an invalid user ID', async () => {
            const result = await userUtils.updateUser(-1, { username: 'newUsername' });
            expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
            expect(result.error).toBe('Invalid user ID');
        });

        it('should return an error response if the user does not exist', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({ rowCount: 0 });
            const result = await userUtils.updateUser(1, { username: 'newUsername' });
            expect(result.statusCode).toBe(StatusCodes.NOT_FOUND);
            expect(result.error).toBe('User not found');
        });

        it('should return an error response if the user is deleted', async () => {
            (dbSessionMock.query as jest.Mock)
                .mockResolvedValueOnce({
                    rowCount: 1,
                    rows: [{ uid: 1, username: 'testUser', created_at: new Date(), display_name: 'Test User', is_deleted: true, shadow_mode: false, full_name_search: false }]
                }); // User exists but is deleted
            const result = await userUtils.updateUser(1, { username: 'newUsername' });
            expect(result.statusCode).toBe(StatusCodes.FORBIDDEN);
            expect(result.error).toBe('Cannot update deleted user');
        });

        it('should return an error response if the username is invalid', async () => {
            (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({
                rowCount: 1,
                rows: [{ uid: 1, is_deleted: false }]
            }); // User exists and is not deleted

            const result = await userUtils.updateUser(1, { username: 'ab' });

            expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
            expect(result.error).toBe(
                'Username must be valid string between 3 and 20 characters and can only contain letters, numbers, and underscores'
            );
        });

        it('should return an error response if the username already exists', async () => {
            (dbSessionMock.query as jest.Mock)
                .mockResolvedValueOnce({ rowCount: 1, rows: [{ uid: 1, is_deleted: false }] }) // User exists
                .mockResolvedValueOnce({ rowCount: 1 }); // Username conflict

            const result = await userUtils.updateUser(1, { username: 'existingUsername' });
            expect(result.statusCode).toBe(StatusCodes.CONFLICT);
            expect(result.error).toBe('Username already exists');
        });

        it('should update the user and return a success response', async () => {
            (dbSessionMock.query as jest.Mock)
                .mockResolvedValueOnce({ rowCount: 1, rows: [{ uid: 1, is_deleted: false }] }) // User exists
                .mockResolvedValueOnce({ rowCount: 0 }) // No username conflict
                .mockResolvedValueOnce({
                    rowCount: 1,
                    rows: [
                        {
                            uid: 1,
                            username: 'updatedUsername',
                            created_at: new Date(),
                            display_name: 'Updated Name',
                            is_deleted: false,
                            shadow_mode: false,
                            full_name_search: false,
                        },
                    ],
                }); // Update query

            const result = await userUtils.updateUser(1, { username: 'updatedUsername', displayName: 'Updated Name' });

            expect(result.statusCode).toBe(StatusCodes.OK);
            expect(result.data?.username).toBe('updatedUsername');
            expect(result.data?.display_name).toBe('Updated Name');
        });

        describe('searchUsers', () => {
            it('should return an error response for an invalid search query', async () => {
                const result = await userUtils.searchUsers('', 10);
                expect(result.statusCode).toBe(StatusCodes.BAD_REQUEST);
                expect(result.error).toBe('Search query is required');
            });

            it('should return a success response with user search results', async () => {
                (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({
                    rowCount: 2,
                    rows: [
                        { uid: 1, username: 'user1', display_name: 'User One', created_at: new Date() },
                        { uid: 2, username: 'user2', display_name: 'User Two', created_at: new Date() }
                    ]
                });

                const result = await userUtils.searchUsers('user', 10);
                expect(result.statusCode).toBe(StatusCodes.OK);
                expect(result.data).toHaveLength(2);
                expect(result.data?.[0].username).toBe('user1');
                expect(result.data?.[1].username).toBe('user2');
            });

            it('should return a success response with a default limit if the limit is invalid', async () => {
                (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({
                    rowCount: 1,
                    rows: [{ uid: 1, username: 'user1', display_name: 'User One', created_at: new Date() }]
                });

                const result = await userUtils.searchUsers('user', -5);
                expect(result.statusCode).toBe(StatusCodes.OK);
                expect(result.data).toHaveLength(1);
                expect(result.data?.[0].username).toBe('user1');
            });

            it('should return an empty result if no users match the query', async () => {
                (dbSessionMock.query as jest.Mock).mockResolvedValueOnce({ rowCount: 0, rows: [] });

                const result = await userUtils.searchUsers('nonexistent', 10);
                expect(result.statusCode).toBe(StatusCodes.OK);
                expect(result.data).toHaveLength(0);
            });
        });
    });
});