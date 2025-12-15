// ./majik-encryption.ts
import { AES } from "@stablelib/aes";
import { GCM } from "@stablelib/gcm";
import { randomBytes } from "@stablelib/random";

/* =======================
   Types
======================= */

export interface AESGCMEncrypted {
    rqc: Uint8Array;       // 256-bit encryption key
    iv: Uint8Array;        // 96-bit nonce used for GCM
    cipher: Uint8Array;    // Encrypted payload
}

/* =======================
   AES-GCM Utility Class
======================= */

export class MajikEncryption {

    /** Generate a random 256-bit AES key */
    static generateKey(): Uint8Array {
        return randomBytes(32); // 32 bytes = 256 bits
    }

    /** Generate a random 96-bit IV for AES-GCM */
    static generateIV(): Uint8Array {
        return randomBytes(12); // 12 bytes = 96 bits recommended for GCM
    }

    /**
     * Encrypt binary data using AES-GCM
     * @param data Uint8Array to encrypt
     * @param rqc 256-bit key
     * @returns AESGCMEncrypted containing cipher + IV + key
     */
    static encrypt(data: Uint8Array, rqc: Uint8Array): AESGCMEncrypted {
        const iv = MajikEncryption.generateIV();
        const aes = new AES(rqc);
        const gcm = new GCM(aes);

        const cipher = gcm.seal(iv, data);

        return { rqc, iv, cipher };
    }

    /**
     * Decrypt AES-GCM encrypted data
     * @param encrypted AESGCMEncrypted object
     * @returns Uint8Array of decrypted binary
     */
    static decrypt(encrypted: AESGCMEncrypted): Uint8Array {
        const { rqc, iv, cipher } = encrypted;
        const aes = new AES(rqc);
        const gcm = new GCM(aes);

        const decrypted = gcm.open(iv, cipher);
        if (!decrypted) {
            throw new Error("Decryption failed or payload was tampered.");
        }
        return decrypted;
    }

    /**
     * Helper: Convert Blob to Uint8Array
     */
    static async blobToUint8Array(blob: Blob): Promise<Uint8Array> {
        const buffer = await blob.arrayBuffer();
        return new Uint8Array(buffer);
    }

  
}
