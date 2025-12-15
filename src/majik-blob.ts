
import {
    appendStrings,
    hashString,
    secureReverse,
    secureTimecode,
} from "./utils";
import { customAlphabet } from "nanoid";
import { AESGCMEncrypted, MajikEncryption } from "./majik-encryption";
import {
    majikCompress,
    majikDecompress
} from "./majik-compress";

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

    /**File extension */
    extension: string;

    /**IV Nonce for AES-GCM */
    i: string;

    /**Compression settings */
    c?: boolean
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
    async getEncryptedBlob(rqx: string, compress: boolean = false): Promise<Blob> {
        const arrayBuffer = await this.file.arrayBuffer();
        let bytes: Uint8Array = new Uint8Array(arrayBuffer);

        if (compress) {
            bytes = await majikCompress(bytes);
        }


        const rqc = MajikBlob.decodeRQX(rqx);
        const keyBytes = new Uint8Array(Buffer.from(rqc, "base64"));

        const encryptedObj: AESGCMEncrypted = MajikEncryption.encrypt(bytes, keyBytes);


        const stx = secureTimecode();
        const rootHash = this.generateRootHash(stx);


        const payload: MajikEncryptedPayload = {
            data: Buffer.from(encryptedObj.cipher).toString("base64"),
            i: Buffer.from(encryptedObj.iv).toString("base64"),
            r: rootHash,
            s: stx,
            sh: hashString(stx),
            h: this.keyHash,
            type: this.file.type || "application/octet-stream",
            extension: this.extension,
            c: compress || false
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
        const keyBytes = new Uint8Array(Buffer.from(rqc, "base64"));

        const encryptedObj: AESGCMEncrypted = {
            rqc: keyBytes,
            iv: new Uint8Array(Buffer.from(payload.i, "base64")),
            cipher: new Uint8Array(Buffer.from(payload.data, "base64"))
        };

        let bytes: Uint8Array = MajikEncryption.decrypt(encryptedObj);

        if (payload.c) {
            bytes = await majikDecompress(bytes);
        }

        // Convert any buffer to a standard ArrayBuffer for Blob
        const arrayBuffer: ArrayBuffer = bytes.buffer instanceof ArrayBuffer
            ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
            : new Uint8Array(bytes).buffer;

        const blobData = new Uint8Array(arrayBuffer, 0, bytes.byteLength);

        const decryptedPayload: MajikDecryptedPayload = {
            data: new Blob([blobData], { type: payload.type }),
            extension: payload.extension,
            type: payload.type
        };

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
       RQC / RQX
    ======================= */

    private static generateRQC(): string {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        return Buffer.from(bytes).toString("base64");
    }

    private static generateRQX(rqc?: string): string {
        // Auto-generate rqc if it's empty or null
        if (!rqc) {
            rqc = this.generateRQC();
        }

        // Decode the input rqc to bytes
        const rqcBytes = Uint8Array.from(Buffer.from(rqc, "base64"));
        const intArray = Array.from(rqcBytes);

        // Reverse the array
        const reversedArray = [...intArray].reverse();

        // Interleave original and reversed arrays
        const interleavedArray: number[] = [];
        for (let i = 0; i < intArray.length; i++) {
            interleavedArray.push(intArray[i], reversedArray[i]);
        }

        // Convert the interleaved array to a base64 string and return
        return Buffer.from(interleavedArray).toString("base64");
    }

    private static decodeRQX(rqx: string): string {
        const bytes = Uint8Array.from(Buffer.from(rqx, "base64"));

        const original: number[] = [];
        const reversed: number[] = [];

        for (let i = 0; i < bytes.length; i += 2) {
            original.push(bytes[i]);
            reversed.push(bytes[i + 1]);
        }

        if (reversed.join() !== [...original].reverse().join())
            throw new Error("Invalid RQX key.");

        return Buffer.from(original).toString("base64");
    }


}


