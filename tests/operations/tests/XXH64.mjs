/**
 * XXH64 tests
 *
 * Reference values were generated with the official xxHash implementation
 * (xxhsum) and cross-checked against xxhash-wasm.
 *
 * @author immanuelabosh
 * @copyright Crown Copyright 2026
 * @license Apache-2.0
 */

import TestRegister from "../../lib/TestRegister.mjs";

TestRegister.addTests([
    {
        name: "XXH64: empty input",
        input: "",
        expectedOutput: "ef46db3751d8e999",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: single byte",
        input: "a",
        expectedOutput: "d24ec4f1a98c6e5b",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: abc",
        input: "abc",
        expectedOutput: "44bc2cf5ad770999",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: input longer than one 32-byte stripe",
        input: "Nobody inspects the spammish repetition",
        expectedOutput: "fbcea83c8a378bf1",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: quick brown fox",
        input: "The quick brown fox jumps over the lazy dog",
        expectedOutput: "0b242d361fda71bc",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: decimal output",
        input: "abc",
        expectedOutput: "4952883123889572249",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0", "Decimal"],
            },
        ],
    },
    {
        name: "XXH64: decimal seed",
        input: "The quick brown fox jumps over the lazy dog",
        expectedOutput: "13f15a4352aa35ef",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["1337", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: hexadecimal seed",
        input: "The quick brown fox jumps over the lazy dog",
        expectedOutput: "13f15a4352aa35ef",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0x539", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: maximum 64-bit seed",
        input: "abc",
        expectedOutput: "28306e589cc02176",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["0xffffffffffffffff", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: seed too large",
        input: "abc",
        expectedOutput: "Seed must fit in 64 bits (maximum 18446744073709551615 / 0xffffffffffffffff).",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["18446744073709551616", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: negative seed",
        input: "abc",
        expectedOutput: "Seed must be a non-negative integer in decimal or hexadecimal (0x...) form.",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["-1", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: non-numeric seed",
        input: "abc",
        expectedOutput: "Seed must be a non-negative integer in decimal or hexadecimal (0x...) form.",
        recipeConfig: [
            {
                op: "XXH64",
                args: ["seed", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: binary input",
        input: "6d797365637265746b65790a00000100001f90",
        expectedOutput: "9dc3ee63bcef8674",
        recipeConfig: [
            {
                op: "From Hex",
                args: ["Auto"],
            },
            {
                op: "XXH64",
                args: ["0", "Hex"],
            },
        ],
    },
    {
        name: "XXH64: HAProxy dynamic cookie (key + IPv4 + port, seed 0)",
        input: "mysecretkey\n10.0.0.1\n8080",
        expectedOutput: "9dc3ee63bcef8674",
        recipeConfig: [
            {
                op: "Subsection",
                args: ["^[^\\n]+", true, false, false],
            },
            {
                op: "To Hex",
                args: ["None", 0],
            },
            {
                op: "Merge",
                args: [true],
            },
            {
                op: "Subsection",
                args: ["(?<=\\n)[^\\n]+(?=\\n)", true, false, false],
            },
            {
                op: "Change IP format",
                args: ["Dotted Decimal", "Hex"],
            },
            {
                op: "Merge",
                args: [true],
            },
            {
                op: "Subsection",
                args: ["[^\\n]+$", true, false, false],
            },
            {
                op: "Change IP format",
                args: ["Decimal", "Hex"],
            },
            {
                op: "Merge",
                args: [true],
            },
            {
                op: "Remove whitespace",
                args: [true, true, true, true, true, false],
            },
            {
                op: "From Hex",
                args: ["Auto"],
            },
            {
                op: "XXH64",
                args: ["0", "Hex"],
            },
        ],
    },
]);
