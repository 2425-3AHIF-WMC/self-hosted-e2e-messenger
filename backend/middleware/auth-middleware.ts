import { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { ServerKeyUtils } from '../utilities/server-key-utils';
import { UserUtils } from '../utilities/user-utils';
import { DbSession } from '../db';

export interface AuthPayload {
    uid: number;
    username: string;
    timestamp: number; 
}

export interface AuthenticatedRequest extends Request {
    user?: {
        uid: number;
        username: string;
    };
}

export async function authenticateToken(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Crypto ')) {
        res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Crypto Authentication header is required' });
        return;
    }

    try {
        const encryptedAuthData = JSON.parse(Buffer.from(authHeader.substring(7), 'base64').toString());
        
        if (!encryptedAuthData.encryptedContentBase64 || !encryptedAuthData.nonceBase64) {
            res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Invalid auth data format' });
            return;
        }

        let userIdFromPath: number | undefined;
        
        if (req.params.uid) {
            userIdFromPath = parseInt(req.params.uid);
        } else if (req.body.uid) {
            userIdFromPath = parseInt(req.body.uid);
        }

        if (!userIdFromPath) {
            // For routes that don't specify a user ID in the path or body
            // We need to extract the user ID from the encrypted data first
            
            // Get a list of all user public keys and try each one
            const dbSession = await DbSession.create(true);
            try {
                const userUtils = new UserUtils(dbSession);
                const users = await userUtils.getAllUsersPublicKeys();
                
                if (!users.data) {
                    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Failed to retrieve user keys' });
                    await dbSession.complete();
                    return;
                }
                
                let authPayload: AuthPayload | null = null;
                
                // Try to decrypt with each user's public key
                for (const user of users.data) {
                    const payload = await ServerKeyUtils.decryptAndVerify<AuthPayload>(
                        encryptedAuthData,
                        user.public_key
                    );
                    
                    if (payload) {
                        authPayload = payload;
                        userIdFromPath = user.uid;
                        break;
                    }
                }
                
                if (!authPayload || !userIdFromPath) {
                    res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Invalid authentication data' });
                    await dbSession.complete();
                    return;
                }
                
                // Check timestamp to prevent replay attacks (5 minute window)
                const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
                if (authPayload.timestamp < fiveMinutesAgo) {
                    res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Authentication timestamp expired' });
                    await dbSession.complete();
                    return;
                }
                
                req.user = {
                    uid: authPayload.uid, 
                    username: authPayload.username
                };
                
                await dbSession.complete();
                next();
                return;
            } catch (error) {
                console.error('Auth error:', error);
                res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Authentication error' });
                await dbSession.complete();
                return;
            }
        }
        
        // If we have a user ID, get their public key
        const dbSession = await DbSession.create(true);
        try {
            const userUtils = new UserUtils(dbSession);
            const userResponse = await userUtils.getUserById(userIdFromPath, userIdFromPath);
            
            if (!userResponse.data) {
                res.status(StatusCodes.UNAUTHORIZED).json({ error: 'User not found' });
                await dbSession.complete();
                return;
            }
            
            const userPublicKey = userResponse.data.public_key;
            
            // Decrypt and verify the auth payload
            const authPayload = await ServerKeyUtils.decryptAndVerify<AuthPayload>(
                encryptedAuthData, 
                userPublicKey
            );
            
            if (!authPayload) {
                res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Invalid authentication data' });
                await dbSession.complete();
                return;
            }
            
            // Check timestamp to prevent replay attacks (5 minute window)
            const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
            if (authPayload.timestamp < fiveMinutesAgo) {
                res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Authentication timestamp expired' });
                await dbSession.complete();
                return;
            }
            
            // Verify that claimed user ID matches the actual user ID from the decrypted payload
            if (authPayload.uid !== userIdFromPath) {
                res.status(StatusCodes.UNAUTHORIZED).json({ error: 'User ID mismatch' });
                await dbSession.complete();
                return;
            }
            
            req.user = {
                uid: authPayload.uid,
                username: authPayload.username
            };
            
            await dbSession.complete();
            next();
        } catch (error) {
            console.error('Auth error:', error);
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ error: 'Authentication error' });
            await dbSession.complete();
        }
    } catch (error) {
        console.error('Auth parsing error:', error);
        res.status(StatusCodes.UNAUTHORIZED).json({ error: 'Invalid authentication data format' });
    }
}
