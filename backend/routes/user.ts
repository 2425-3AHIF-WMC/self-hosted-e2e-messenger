import { Router, Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { UserUtils, UserResponse, BasicUserResponse } from '../utilities/user-utils';
import { DbSession } from '../db';
import { AuthenticatedRequest, authenticateToken } from '../middleware/auth-middleware';
import { ServerKeyUtils } from '../utilities/server-key-utils';

export const userRouter = Router();

userRouter.post('/', async (req: Request, res: Response) => {
    const { username, password, displayName, shadowMode, fullNameSearch, publicKey } = req.body;

    let dbSession = await DbSession.create(false);
    try {
        const userUtils = new UserUtils(dbSession);

        const response: UserResponse = await userUtils.createUser(
            username, 
            password,
            publicKey,
            displayName,
            shadowMode,
            fullNameSearch,
        );

        res.status(response.statusCode).json(
            response.data !== null ? response.data : { error: response.error }
        );
        await dbSession.complete(true);
    } catch (error) {
        console.error(error);

        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while processing your request"
        });
        await dbSession.complete(false);
    }
});

userRouter.get('/search', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const { query, limit = 20 } = req.query;

    if (!query || typeof query !== 'string') {
        res.status(StatusCodes.BAD_REQUEST).json({
            error: 'Search query is required'
        });
        return;
    }

    const searchLimit = typeof limit === 'string' ? parseInt(limit) : 20;

    const dbSession = await DbSession.create(true);
    try {
        const userUtils = new UserUtils(dbSession);
        const response = await userUtils.searchUsers(query, searchLimit);

        res.status(response.statusCode).json(
            response.data !== null ? response.data : { error: response.error }
        );
    } catch (error) {
        console.error('Error searching for users:', error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while processing your request"
        });
    } finally {
        await dbSession.complete();
    }
});

userRouter.get('/:uid', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const uid: number = parseInt(req.params.uid);

    let dbSession = await DbSession.create(true);
    try {
        const userUtils = new UserUtils(dbSession);

        const response: BasicUserResponse = await userUtils.getUserById(uid, req.user?.uid || 0);

        res.status(response.statusCode).json(
            response.data !== null ? response.data : { error: response.error }
        );
    } catch (error) {
        console.error(error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while processing your request"
        });
    } finally {
        await dbSession.complete();
    }
});

userRouter.post('/login', async (req: Request, res: Response) => {
    const { username, password } = req.body;

    let dbSession = await DbSession.create(true);
    try {
        const userUtils = new UserUtils(dbSession);

        const response: UserResponse = await userUtils.loginUser(username, password);

        res.status(response.statusCode).json(
            response.data !== null ? response.data : { error: response.error }
        );
    } catch (error) {
        console.error(error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while processing your request"
        });
    } finally {
        await dbSession.complete();
    }
});

userRouter.delete('/:uid', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const uid = parseInt(req.params.uid);

    if (uid !== req.user?.uid) {
        res.status(StatusCodes.FORBIDDEN).json({
            error: 'You can only delete your own account'
        });
        return;
    }

    let dbSession = await DbSession.create(false);
    try {
        const userUtils = new UserUtils(dbSession);

        const result = await userUtils.deleteUser(uid);

        await dbSession.complete(result.statusCode === StatusCodes.OK);

        if (result.statusCode === StatusCodes.OK) {
            res.sendStatus(result.statusCode);
        } else {
            res.status(result.statusCode).json({ error: result.error });
        }
    } catch (error) {
        console.error(error);
        await dbSession.complete(false);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while processing your request"
        });
    }
});

userRouter.put('/:uid', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const uid = parseInt(req.params.uid);
    const { username, displayName, shadowMode, fullNameSearch } = req.body;

    if (uid !== req.user?.uid) {
        res.status(StatusCodes.FORBIDDEN).json({
            error: 'You can only update your own account'
        });
        return;
    }

    if (username === undefined && 
        displayName === undefined && 
        shadowMode === undefined && 
        fullNameSearch === undefined) {
        res.status(StatusCodes.BAD_REQUEST).json({
            error: 'Must provide at least one field to update'
        });
        return;
    }

    let dbSession = await DbSession.create(false);
    try {
        const userUtils = new UserUtils(dbSession);

        const result = await userUtils.updateUser(uid, {
            username,
            displayName,
            shadowMode,
            fullNameSearch
        });

        await dbSession.complete(result.statusCode === StatusCodes.OK);

        if (result.statusCode === StatusCodes.OK) {
            res.status(result.statusCode).json(result.data);
        } else {
            res.status(result.statusCode).json({ error: result.error });
        }
    } catch (error) {
        console.error(error);
        await dbSession.complete(false);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while processing your request"
        });
    }
});

userRouter.put('/:uid/password', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const uid = parseInt(req.params.uid);
    const { currentPassword, newPassword } = req.body;

    if (uid !== req.user?.uid) {
        res.status(StatusCodes.FORBIDDEN).json({
            error: 'You can only update your own password'
        });
        return;
    }

    if (!currentPassword || !newPassword) {
        res.status(StatusCodes.BAD_REQUEST).json({
            error: 'Both current and new password are required'
        });
        return;
    }

    let dbSession = await DbSession.create(false);
    try {
        const userUtils = new UserUtils(dbSession);

        const result = await userUtils.updatePassword(uid, currentPassword, newPassword);

        await dbSession.complete(result.statusCode === StatusCodes.OK);

        if (result.statusCode === StatusCodes.OK) {
            res.status(result.statusCode).json(result.data);
        } else {
            res.status(result.statusCode).json({ error: result.error });
        }
    } catch (error) {
        console.error(error);
        await dbSession.complete(false);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while updating password"
        });
    }
});

userRouter.put('/:uid/keys', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const uid = parseInt(req.params.uid);
    const { publicKey } = req.body;

    if (uid !== req.user?.uid) {
        res.status(StatusCodes.FORBIDDEN).json({
            error: 'You can only update your own keys'
        });
        return;
    }

    let dbSession = await DbSession.create(false);
    try {
        const userUtils = new UserUtils(dbSession);

        const response: UserResponse = await userUtils.updatePublicKey(uid, publicKey);

        await dbSession.complete(response.statusCode === StatusCodes.OK);
        
        res.status(response.statusCode).json(
            response.data !== null ? response.data : { error: response.error }
        );
    } catch (error) {
        console.error(error);
        await dbSession.complete(false);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            error: "An unexpected error occurred while processing your request"
        });
    }
});

userRouter.get('/server-key', (req: Request, res: Response) => {
    try {
        const publicKey = ServerKeyUtils.getPublicKey();
        res.status(StatusCodes.OK).json({ publicKey });
    } catch (error) {
        console.error('Error getting server public key:', error);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ 
            error: 'An error occurred while retrieving server public key' 
        });
    }
});
