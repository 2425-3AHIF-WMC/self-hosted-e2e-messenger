import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import path, { dirname, join } from 'path';
import { userRouter } from './routes/user';
import { DbSession } from './db';
import { fileURLToPath } from 'url';
import { contactRouter } from './routes/contact';
import { msgRouter } from './routes/message';
import http from 'http';
import { Server } from 'socket.io';
import { ServerKeyUtils } from './utilities/server-key-utils';

dotenv.config({
    path: path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        '../.env'
    ),
});

// Initialize server keys
await ServerKeyUtils.initialize();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL,
        methods: ["GET", "POST"],
        credentials: true
    }
});

// Socket.IO connection handling with crypto authentication
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);
    
    // Verify user authentication data
    const auth = socket.handshake.auth?.user;
    if (!auth || !auth.uid || !auth.username || !auth.public_key) {
        console.error('Invalid authentication data');
        socket.disconnect();
        return;
    }
    
    // Join user to a personal room based on their user ID
    socket.on('join', (userId) => {
        // Verify that the joined userId matches the authenticated user
        if (userId !== auth.uid) {
            console.error('User ID mismatch in join request');
            return;
        }
        
        socket.join(`user_${userId}`);
        console.log(`User ${userId} joined their room`);
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

// Export io so it can be used in other files
export { io };

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

app.use('/user', userRouter);
app.use('/contact', contactRouter);
app.use('/message', msgRouter);

if (!process.env.BACKEND_PORT) {
    throw new Error('BACKEND_PORT is not set');
}

server.listen(process.env.BACKEND_PORT, async () => {
    await DbSession.ensureTablesCreated();
    console.log(`running on http://localhost:${process.env.BACKEND_PORT}`);
});
