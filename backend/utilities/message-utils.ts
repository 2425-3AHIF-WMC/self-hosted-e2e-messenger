import { StatusCodes } from "http-status-codes";
import { IMessage } from "../models/message-model";
import { BaseResponse, Utils } from "./utils";

export type MessageResponse = BaseResponse<IMessage[]>

export class MessageUtils extends Utils {

    /**
     * Send a message from one user to another to the database unencrypted 
     * @param sender_uid Sender User ID 
     * @param receiver_uid Receiver User ID
     * @param content Message content
     * @returns A MessageResponse object containing statusCode, data, and optional error message
     */
    async sendMessage(sender_uid: number, receiver_uid: number, content: string): Promise<BaseResponse<IMessage>> {
        if (!this.isValidUserId(sender_uid) || !this.isValidUserId(receiver_uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid UID'
            );
        }

        if (!(await this.userExists(sender_uid)) || !(await this.userExists(receiver_uid))) {
            return this.createErrorResponse(
                StatusCodes.NOT_FOUND,
                'User not found'
            );
        }

        if (sender_uid === receiver_uid) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Cannot send message to self'
            );
        }

        if (!(await this.hasContactWith(sender_uid, receiver_uid))) {
            return this.createErrorResponse(
                StatusCodes.FORBIDDEN,
                'Users are not contacts'
            );
        }

        // Check if the user can send messages and get specific reason if not
        const messagePermission = await this.canSendMessage(sender_uid, receiver_uid);
        if (!messagePermission.canSend) {
            // Provide more specific error messages based on the reason
            if (messagePermission.reason === 'you_blocked') {
                return this.createErrorResponse(
                    StatusCodes.FORBIDDEN,
                    'Cannot message, you have blocked this user'
                );
            } else if (messagePermission.reason === 'user_blocked') {
                return this.createErrorResponse(
                    StatusCodes.FORBIDDEN,
                    'Cannot message user, user has blocked you'
                );
            } else {
                // Default message for other cases
                return this.createErrorResponse(
                    StatusCodes.FORBIDDEN,
                    'Cannot send message to this user'
                );
            }
        }

        try {
            const result = await this.dbSession.query(`
            INSERT INTO message (sender_uid, receiver_uid, content)
            VALUES ($1, $2, $3)
            RETURNING mid, sender_uid, receiver_uid, content, timestamp`,
                [sender_uid, receiver_uid, content]
            );

            if (result.rowCount === 0) {
                return this.createErrorResponse(
                    StatusCodes.INTERNAL_SERVER_ERROR,
                    'Failed to send message'
                );
            }

            const message: IMessage = {
                mid: result.rows[0].mid,
                sender_uid: result.rows[0].sender_uid,
                receiver_uid: result.rows[0].receiver_uid,
                content: result.rows[0].content,
                timestamp: result.rows[0].timestamp
            };

            return this.createSuccessResponse(message);
        } catch (error) {
            console.error('Error sending message:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'Failed to send message.'
            );
        }
    }

    /**
     * Fetches messages between two users
     * @param sender_uid The ID of the sender
     * @param receiver_uid The ID of the receiver
     * @returns A MessageResponse object containing statusCode, data, and optional error message
     */
    public async fetchMessage(sender_uid: number, receiver_uid: number): Promise<MessageResponse> {
        if (!this.isValidUserId(sender_uid) || !this.isValidUserId(receiver_uid)) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Invalid UID'
            );
        }

        if (!(await this.userExists(sender_uid)) || !(await this.userExists(receiver_uid))) {
            return this.createErrorResponse(
                StatusCodes.NOT_FOUND,
                'User not found'
            );
        }

        if (sender_uid === receiver_uid) {
            return this.createErrorResponse(
                StatusCodes.BAD_REQUEST,
                'Cannot fetch messages with self'
            );
        }

        try {
            const result = await this.dbSession.query(`
            SELECT m.mid, m.sender_uid, m.receiver_uid, m.content, m.timestamp
            FROM message m
            WHERE (m.sender_uid = $1 AND m.receiver_uid = $2) 
               OR (m.sender_uid = $2 AND m.receiver_uid = $1)
            ORDER BY m.timestamp ASC`,
                [sender_uid, receiver_uid]
            );

            const messages: IMessage[] = result.rows.map(row => ({
                mid: row.mid,
                sender_uid: row.sender_uid,
                receiver_uid: row.receiver_uid,
                content: row.content,
                timestamp: row.timestamp
            }));

            return this.createSuccessResponse(messages);
        } catch (error) {
            console.error('Error fetching messages:', error);
            return this.createErrorResponse(
                StatusCodes.INTERNAL_SERVER_ERROR,
                'Failed to fetch messages.'
            );
        }
    }
}
