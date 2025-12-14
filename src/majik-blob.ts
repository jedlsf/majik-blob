import fernet from "fernet";

import {
    appendStrings,
    hashString,
    secureReverse,
    secureTimecode,
} from "./utils";
import { customAlphabet } from "nanoid";

/* =======================
   Types
======================= */

export interface MajikEncryptedPayload {
    /** Encrypted binary payload (base64) */
    data: string;

    /** Root hash */
    r: string;

    /** STX timestamp */
    s: string;

    /** Hash of STX */
    sh: string;

    /** Hash of user key */
    h: string;

    /** Original MIME type */
    type: string;

    extension: string;
}

export interface MajikDecryptedPayload {
    /** Decrypted File */
    data: Blob;

    /** Original MIME type */
    type: string;

    extension: string;
}

export interface MajikBlobKey {
    key: string;
    rqx: string;

}

/* =======================
   MajikBlob
======================= */

export class MajikBlob {
    private readonly key: string;
    private readonly keyHash: string;
    private readonly file: Blob;
    private readonly extension: string;

    constructor(key: string, file: Blob, extension?: string) {
        if (!key?.trim()) throw new Error("Encryption key required.");
        if (!(file instanceof Blob)) throw new Error("Invalid file blob.");

        this.key = key;
        this.keyHash = hashString(key);
        this.file = file;
        this.extension =
            extension ||
            file.type?.split("/")[1] ||
            "bin";
    }

    /* =======================
       Public API
    ======================= */

    /** Returns encrypted Blob ready for download */
    async getEncryptedBlob(rqx: string): Promise<Blob> {
        const arrayBuffer = await this.file.arrayBuffer();
        const binary = this.arrayBufferToBase64(arrayBuffer);

        const stx = secureTimecode();
        const rootHash = this.generateRootHash(stx);

        const rqc = MajikBlob.decodeRQX(rqx);

        const encrypted = MajikBlob.encrypt(binary, rqc);

        const payload: MajikEncryptedPayload = {
            data: encrypted,
            r: rootHash,
            s: stx,
            sh: hashString(stx),
            h: this.keyHash,
            type: this.file.type || "application/octet-stream",
            extension: this.extension
        };

        return new Blob([JSON.stringify(payload)], {
            type: "application/majik-blob"
        });
    }

    /** Decrypts an encrypted MajikBlob back to original file */
    static async decryptEncryptedBlob(
        encryptedBlob: Blob,
        key: string,
        rqx: string,
    ): Promise<MajikDecryptedPayload> {
        const text = await encryptedBlob.text();
        const payload = JSON.parse(text) as MajikEncryptedPayload;

        this.validatePayload(payload, key);

        const rqc = this.decodeRQX(rqx);

        const decryptedBase64 = this.decrypt(payload.data, rqc);

        const buffer = this.base64ToArrayBuffer(decryptedBase64);

        const decryptedPayload: MajikDecryptedPayload = {
            data: new Blob([buffer], { type: payload.type }),
            extension: payload.extension,
            type: payload.type
        }
        return decryptedPayload;
    }

    /**
    * Returns the original file extension stored in the encrypted MajikBlob payload.
    * @param encryptedBlob The Blob returned by getEncryptedBlob()
    * @returns Promise<string> The original file extension (e.g., "glb", "mp3")
    */
    static async getEncryptedFileExtension(encryptedBlob: Blob): Promise<string> {
        if (!(encryptedBlob instanceof Blob))
            throw new Error("Invalid Blob provided.");

        const text = await encryptedBlob.text();
        try {
            const payload = JSON.parse(text) as MajikEncryptedPayload;
            if (!payload.extension || typeof payload.extension !== "string") {
                throw new Error("No extension found in payload.");
            }
            return payload.extension;
        } catch (error) {
            throw new Error("Failed to parse encrypted payload: " + error);
        }
    }


    /* =======================
       Key Generation
    ======================= */

    static generateKey(characters: number = 32): MajikBlobKey {


        const rqx = MajikBlob.generateRQX();

        const generateID = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', characters);
        const blobKey = generateID();

        const keyPayload: MajikBlobKey = {
            key: blobKey,
            rqx: rqx,
        };


        return keyPayload;
    }


    /* =======================
       Root Integrity
    ======================= */

    private generateRootHash(stx: string): string {
        return hashString(
            appendStrings([
                secureReverse(stx),
                this.key,
                stx,
                this.keyHash
            ])
        );
    }

    private static validatePayload(
        payload: MajikEncryptedPayload,
        key: string
    ): void {
        if (hashString(key) !== payload.h)
            throw new Error("Invalid decryption key.");

        if (hashString(payload.s) !== payload.sh)
            throw new Error("STX hash mismatch.");


        const rootCheck = hashString(
            appendStrings([
                secureReverse(payload.s),
                key,
                payload.s,
                payload.h
            ])
        );

        if (rootCheck !== payload.r)
            throw new Error("Encrypted blob tampered.");
    }

    /* =======================
       Fernet Crypto
    ======================= */

    private static encrypt(data: string, rqc: string): string {
        const token = new fernet.Token({
            secret: new fernet.Secret(rqc),
            ttl: 0
        });
        return token.encode(data);
    }

    private static decrypt(token: string, rqc: string): string {
        const t = new fernet.Token({
            secret: new fernet.Secret(rqc),
            token,
            ttl: 0
        });
        return t.decode();
    }

    /* =======================
       RQC / RQX
    ======================= */

    private static generateRQC(): string {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        return btoa(String.fromCharCode(...bytes));
    }

    private static generateRQX(rqc?: string): string {
        // Auto-generate rqc if it's empty or null
        if (!rqc) {
            rqc = this.generateRQC();
        }

        // Decode the input rqc to bytes
        const rqcBytes = Uint8Array.from(atob(rqc), (c) => c.charCodeAt(0)); // Decode base64 to byte array
        const intArray = Array.from(rqcBytes);

        // Reverse the array
        const reversedArray = [...intArray].reverse();

        // Interleave original and reversed arrays
        const interleavedArray: number[] = [];
        for (let i = 0; i < intArray.length; i++) {
            interleavedArray.push(intArray[i], reversedArray[i]);
        }

        // Convert the interleaved array to a base64 string and return
        return btoa(String.fromCharCode(...interleavedArray)); // Convert the byte array to base64 string
    }

    private static decodeRQX(rqx: string): string {
        const bytes = Uint8Array.from(atob(rqx), c => c.charCodeAt(0));
        const original: number[] = [];
        const reversed: number[] = [];

        for (let i = 0; i < bytes.length; i += 2) {
            original.push(bytes[i]);
            reversed.push(bytes[i + 1]);
        }

        if (reversed.join() !== [...original].reverse().join())
            throw new Error("Invalid RQX key.");

        return btoa(String.fromCharCode(...original));
    }

    /* =======================
       Binary Helpers
    ======================= */

    private arrayBufferToBase64(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000; // 32KB chunks
        let binary = "";

        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode(
                ...bytes.subarray(i, i + chunkSize)
            );
        }

        return btoa(binary);
    }


    private static base64ToArrayBuffer(base64: string): ArrayBuffer {
        const bin = atob(base64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) {
            bytes[i] = bin.charCodeAt(i);
        }
        return bytes.buffer;
    }
}


