/**
 * @author Immanuel Abosh
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";

const PRIME64_1 = 0x9E3779B185EBCA87n;
const PRIME64_2 = 0xC2B2AE3D27D4EB4Fn;
const PRIME64_3 = 0x165667B19E3779F9n;
const PRIME64_4 = 0x85EBCA77C2B2AE63n;
const PRIME64_5 = 0x27D4EB2F165667C5n;
const MASK64 = 0xFFFFFFFFFFFFFFFFn;
const MAX_SEED = 0xFFFFFFFFFFFFFFFFn;

/**
 * XXH64 operation
 */
class XXH64 extends Operation {

    /**
     * XXH64 constructor
     */
    constructor() {
        super();

        this.name = "XXH64";
        this.module = "Hashing";
        this.description = "Generates the 64-bit xxHash (XXH64) digest of the input.<br><br>xxHash is an extremely fast non-cryptographic hash algorithm created by Yann Collet. XXH64 is used by, among others, HAProxy to generate dynamic persistence cookies (<code>dynamic-cookie-key</code>), by LZ4 and Zstandard for frame checksums, and by many databases and file systems for fast integrity checks.<br><br>The optional seed is a 64-bit unsigned integer and may be entered in decimal or hexadecimal (prefixed with <code>0x</code>). The output is the big-endian hexadecimal representation of the digest, zero-padded to 16 characters, matching the canonical form used by the <code>xxhsum</code> tool.";
        this.infoURL = "https://wikipedia.org/wiki/List_of_hash_functions#Non-cryptographic_hash_functions";
        this.inputType = "ArrayBuffer";
        this.outputType = "string";
        this.args = [
            {
                name: "Seed",
                type: "string",
                value: "0"
            },
            {
                name: "Output format",
                type: "option",
                value: ["Hex", "Decimal"]
            }
        ];
    }

    /**
     * Parses the seed argument into a 64-bit unsigned BigInt.
     *
     * @param {string} seed
     * @returns {bigint}
     */
    static parseSeed(seed) {
        const str = String(seed).trim();
        if (!/^(0x[0-9a-f]+|\d+)$/i.test(str)) {
            throw new OperationError("Seed must be a non-negative integer in decimal or hexadecimal (0x...) form.");
        }
        const value = BigInt(str);
        if (value > MAX_SEED) {
            throw new OperationError("Seed must fit in 64 bits (maximum 18446744073709551615 / 0xffffffffffffffff).");
        }
        return value;
    }

    /**
     * Calculates the XXH64 hash of the given bytes.
     *
     * @param {Uint8Array} data
     * @param {bigint} seed - 64-bit unsigned seed
     * @returns {bigint} 64-bit unsigned digest
     */
    static hash(data, seed) {
        const len = data.length;
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let h64;
        let offset = 0;

        if (len >= 32) {
            let v1 = (seed + PRIME64_1 + PRIME64_2) & MASK64;
            let v2 = (seed + PRIME64_2) & MASK64;
            let v3 = seed;
            let v4 = (seed - PRIME64_1) & MASK64;

            const limit = len - 32;
            do {
                v1 = XXH64.round(v1, view.getBigUint64(offset, true));
                v2 = XXH64.round(v2, view.getBigUint64(offset + 8, true));
                v3 = XXH64.round(v3, view.getBigUint64(offset + 16, true));
                v4 = XXH64.round(v4, view.getBigUint64(offset + 24, true));
                offset += 32;
            } while (offset <= limit);

            h64 = (XXH64.rotl(v1, 1n) + XXH64.rotl(v2, 7n) + XXH64.rotl(v3, 12n) + XXH64.rotl(v4, 18n)) & MASK64;
            h64 = XXH64.mergeRound(h64, v1);
            h64 = XXH64.mergeRound(h64, v2);
            h64 = XXH64.mergeRound(h64, v3);
            h64 = XXH64.mergeRound(h64, v4);
        } else {
            h64 = (seed + PRIME64_5) & MASK64;
        }

        h64 = (h64 + BigInt(len)) & MASK64;

        while (offset + 8 <= len) {
            const k1 = XXH64.round(0n, view.getBigUint64(offset, true));
            h64 ^= k1;
            h64 = (XXH64.rotl(h64, 27n) * PRIME64_1 + PRIME64_4) & MASK64;
            offset += 8;
        }

        if (offset + 4 <= len) {
            h64 ^= (BigInt(view.getUint32(offset, true)) * PRIME64_1) & MASK64;
            h64 = (XXH64.rotl(h64, 23n) * PRIME64_2 + PRIME64_3) & MASK64;
            offset += 4;
        }

        while (offset < len) {
            h64 ^= (BigInt(data[offset]) * PRIME64_5) & MASK64;
            h64 = (XXH64.rotl(h64, 11n) * PRIME64_1) & MASK64;
            offset++;
        }

        h64 ^= h64 >> 33n;
        h64 = (h64 * PRIME64_2) & MASK64;
        h64 ^= h64 >> 29n;
        h64 = (h64 * PRIME64_3) & MASK64;
        h64 ^= h64 >> 32n;

        return h64;
    }

    /**
     * Rotates a 64-bit value left by the given number of bits.
     *
     * @param {bigint} x
     * @param {bigint} r
     * @returns {bigint}
     */
    static rotl(x, r) {
        return ((x << r) | (x >> (64n - r))) & MASK64;
    }

    /**
     * XXH64 accumulator round.
     *
     * @param {bigint} acc
     * @param {bigint} input
     * @returns {bigint}
     */
    static round(acc, input) {
        acc = (acc + input * PRIME64_2) & MASK64;
        acc = XXH64.rotl(acc, 31n);
        return (acc * PRIME64_1) & MASK64;
    }

    /**
     * XXH64 merge round, used to fold the four lanes into the final hash.
     *
     * @param {bigint} acc
     * @param {bigint} val
     * @returns {bigint}
     */
    static mergeRound(acc, val) {
        val = XXH64.round(0n, val);
        acc ^= val;
        return (acc * PRIME64_1 + PRIME64_4) & MASK64;
    }

    /**
     * @param {ArrayBuffer} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [seedArg, outputFormat] = args;
        const seed = XXH64.parseSeed(seedArg);
        const digest = XXH64.hash(new Uint8Array(input), seed);

        if (outputFormat === "Decimal") {
            return digest.toString(10);
        }
        return digest.toString(16).padStart(16, "0");
    }

}

export default XXH64;
