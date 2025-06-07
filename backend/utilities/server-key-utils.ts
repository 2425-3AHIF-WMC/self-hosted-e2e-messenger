import sodium from 'libsodium-wrappers';

interface ServerKeys {
    publicKey: string;
    privateKey: string;
}

export class ServerKeyUtils {
    private static serverKeys: ServerKeys | null = null;

    /**
     * Initialize the server keys - generates new keys on each startup
     */
    static async initialize(): Promise<void> {
        await sodium.ready;
        console.log('Generating new server keys on startup...');
        await this.generateServerKeys();
    }

    /**
     * Generate a new keypair for the server
     */
    private static async generateServerKeys(): Promise<void> {
        await sodium.ready;
        const keyPair = sodium.crypto_kx_keypair();
        
        this.serverKeys = {
            publicKey: sodium.to_base64(keyPair.publicKey, sodium.base64_variants.ORIGINAL),
            privateKey: sodium.to_base64(keyPair.privateKey, sodium.base64_variants.ORIGINAL)
        };
        
        console.log('Server keys generated successfully');
    }

    /**
     * Get the server's public key
     */
    static getPublicKey(): string {
        if (!this.serverKeys) {
            throw new Error('Server keys have not been initialized');
        }
        return this.serverKeys.publicKey;
    }

    /**
     * Get the server's private key
     * @returns 
     */
    static getPrivateKey(): string {
        if (!this.serverKeys) {
            throw new Error('Server keys have not been initialized');
        }
        return this.serverKeys.privateKey;
    }

    /**
     * Decrypt and verify a message using the server's private key and the user's public key
     * @param encryptedMessage Encrypted message from the client
     * @param userPublicKey User's public key
     * @returns Decrypted payload or null if verification failed
     */
    static async decryptAndVerify<T>(encryptedMessage: {
        encryptedContentBase64: string;
        nonceBase64: string;
    }, userPublicKey: string): Promise<T | null> {
        await sodium.ready;
        
        if (!this.serverKeys) {
            throw new Error('Server keys have not been initialized');
        }

        try {
            // Convert base64 to Uint8Array
            const encryptedContent = sodium.from_base64(
                encryptedMessage.encryptedContentBase64,
                sodium.base64_variants.ORIGINAL
            );
            const nonce = sodium.from_base64(
                encryptedMessage.nonceBase64,
                sodium.base64_variants.ORIGINAL
            );
            const serverPrivateKey = sodium.from_base64(
                this.serverKeys.privateKey,
                sodium.base64_variants.ORIGINAL
            );
            const serverPublicKey = sodium.from_base64(
                this.serverKeys.publicKey,
                sodium.base64_variants.ORIGINAL
            );
            const userPubKey = sodium.from_base64(
                userPublicKey,
                sodium.base64_variants.ORIGINAL
            );

            const sharedKeys = sodium.crypto_kx_server_session_keys(
                serverPublicKey,
                serverPrivateKey,
                userPubKey
            );
            
            const decryptedMessage = sodium.to_string(
                sodium.crypto_secretbox_open_easy(
                    encryptedContent,
                    nonce,
                    sharedKeys.sharedRx
                )
            );
            
            return JSON.parse(decryptedMessage) as T;
        } catch (error) {
            console.error('Error decrypting auth message:', error);
            return null;
        }
    }
}
