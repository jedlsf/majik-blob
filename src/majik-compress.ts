// ./majik-compress.ts
import { init, compress, decompress } from "@bokuweb/zstd-wasm";

let initialized = false;

async function ensureInit() {
    if (!initialized) {
        await init();
        initialized = true;
    }
}

/** Compress raw binary data */
export async function majikCompress(
    data: Uint8Array,
    level: number = 9
): Promise<Uint8Array> {
    await ensureInit();
    return compress(data, level);
}

/** Decompress raw binary data */
export async function majikDecompress(
    data: Uint8Array
): Promise<Uint8Array> {
    await ensureInit();
    return decompress(data);
}
