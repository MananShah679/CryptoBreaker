/**
 * Modern Cipher Module
 * Educational implementations of RSA, DES, and AES with step-by-step output
 */

// ==================== MATH HELPERS ====================

/**
 * Extended Euclidean Algorithm
 * Returns { gcd, x, y } where gcd = a*x + b*y
 */
export function extendedGCD(a, b) {
    const steps = [];
    let oldR = a, r = b;
    let oldS = 1n, s = 0n;
    let oldT = 0n, t = 1n;

    while (r !== 0n) {
        const quotient = oldR / r;
        steps.push({
            q: quotient,
            r: oldR,
            s: oldS,
            t: oldT
        });

        [oldR, r] = [r, oldR - quotient * r];
        [oldS, s] = [s, oldS - quotient * s];
        [oldT, t] = [t, oldT - quotient * t];
    }

    steps.push({ gcd: oldR, x: oldS, y: oldT });

    return { gcd: oldR, x: oldS, y: oldT, steps };
}

/**
 * Modular Inverse using Extended Euclidean Algorithm
 */
export function modInverseBigInt(a, m) {
    const { gcd, x } = extendedGCD(BigInt(a), BigInt(m));
    if (gcd !== 1n) {
        throw new Error(`No modular inverse exists for ${a} mod ${m}`);
    }
    return ((x % BigInt(m)) + BigInt(m)) % BigInt(m);
}

/**
 * Euler's Totient Function (Phi)
 * φ(n) = count of integers from 1 to n that are coprime to n
 */
export function eulerPhi(n) {
    const steps = [];
    const factors = primeFactorization(n);
    steps.push({ step: 'Prime Factorization', factors });

    let result = n;
    const uniquePrimes = [...new Set(factors)];

    for (const p of uniquePrimes) {
        result = result - (result / p);
        steps.push({ step: `Subtract n/p for prime ${p}`, result });
    }

    // Alternative formula: φ(n) = n * ∏(1 - 1/p)
    let phi = n;
    for (const p of uniquePrimes) {
        phi = Math.floor(phi * (p - 1) / p);
    }

    steps.push({ step: 'Final φ(n)', result: phi });

    return { phi, steps };
}

/**
 * Prime Factorization
 */
export function primeFactorization(n) {
    const factors = [];
    let d = 2;
    while (n > 1) {
        while (n % d === 0) {
            factors.push(d);
            n /= d;
        }
        d++;
        if (d * d > n && n > 1) {
            factors.push(n);
            break;
        }
    }
    return factors;
}

/**
 * Modular Exponentiation (for large numbers)
 * Computes base^exp mod m efficiently
 */
export function modPow(base, exp, mod) {
    base = BigInt(base);
    exp = BigInt(exp);
    mod = BigInt(mod);

    let result = 1n;
    base = base % mod;

    const steps = [];

    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
            steps.push({ exp: exp.toString(), result: result.toString() });
        }
        exp = exp / 2n;
        base = (base * base) % mod;
    }

    return { result: Number(result), steps };
}

// ==================== RSA ====================

/**
 * RSA Key Generation with step-by-step output
 */
export function rsaGenerateKeys(p, q, e = null) {
    const steps = [];

    // Step 1: Calculate n
    const n = p * q;
    steps.push({ step: 1, description: 'Calculate n = p × q', formula: `n = ${p} × ${q}`, result: n });

    // Step 2: Calculate φ(n) = (p-1)(q-1)
    const phi = (p - 1) * (q - 1);
    steps.push({ step: 2, description: 'Calculate φ(n) = (p-1)(q-1)', formula: `φ(n) = (${p}-1)(${q}-1) = ${p - 1} × ${q - 1}`, result: phi });

    // Step 3: Choose e if not provided (common: 7, 17, 65537)
    if (e === null) {
        for (const candidate of [7, 17, 65537, 3]) {
            if (gcdNum(candidate, phi) === 1 && candidate < phi) {
                e = candidate;
                break;
            }
        }
    }
    steps.push({ step: 3, description: 'Choose e (coprime with φ(n))', formula: `gcd(${e}, ${phi}) = 1`, result: e });

    // Step 4: Calculate d = e^(-1) mod φ(n)
    const d = Number(modInverseBigInt(e, phi));
    steps.push({ step: 4, description: 'Calculate d = e⁻¹ mod φ(n)', formula: `d = ${e}⁻¹ mod ${phi}`, result: d });

    // Verification
    const verification = (e * d) % phi;
    steps.push({ step: 5, description: 'Verify: e × d ≡ 1 (mod φ(n))', formula: `${e} × ${d} mod ${phi} = ${verification}`, result: verification === 1 ? 'Valid ✓' : 'Invalid ✗' });

    return {
        publicKey: { e, n },
        privateKey: { d, n },
        phi,
        steps
    };
}

/**
 * RSA Encryption with step-by-step output
 */
export function rsaEncrypt(message, e, n) {
    const steps = [];

    steps.push({ step: 1, description: 'Apply encryption formula', formula: `C = M^e mod n = ${message}^${e} mod ${n}` });

    const { result: ciphertext, steps: powSteps } = modPow(message, e, n);

    steps.push({ step: 2, description: 'Modular exponentiation steps', details: powSteps });
    steps.push({ step: 3, description: 'Ciphertext', result: ciphertext });

    return { ciphertext, steps };
}

/**
 * RSA Decryption with step-by-step output
 */
export function rsaDecrypt(ciphertext, d, n) {
    const steps = [];

    steps.push({ step: 1, description: 'Apply decryption formula', formula: `M = C^d mod n = ${ciphertext}^${d} mod ${n}` });

    const { result: plaintext, steps: powSteps } = modPow(ciphertext, d, n);

    steps.push({ step: 2, description: 'Modular exponentiation steps', details: powSteps });
    steps.push({ step: 3, description: 'Plaintext', result: plaintext });

    return { plaintext, steps };
}

function gcdNum(a, b) {
    return b === 0 ? a : gcdNum(b, a % b);
}

// ==================== DES (SIMPLIFIED EDUCATIONAL) ====================

// DES S-Boxes
const DES_SBOXES = [
    // S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    // S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    // S3-S8 would be here in full implementation
];

/**
 * DES Educational Demo
 * Shows the structure without full implementation
 */
export function desDemo(plaintext, key) {
    const steps = [];

    // Convert to binary representation (simplified)
    const plaintextBin = textToBinary(plaintext.substring(0, 8));
    const keyBin = textToBinary(key.substring(0, 8));

    steps.push({
        step: 'Input',
        plaintext: plaintext.substring(0, 8),
        plaintextBinary: plaintextBin,
        key: key.substring(0, 8),
        keyBinary: keyBin
    });

    // Initial Permutation (IP)
    steps.push({
        step: 'Initial Permutation (IP)',
        description: '64-bit plaintext is permuted according to IP table'
    });

    // Split into L0 and R0
    steps.push({
        step: 'Split',
        description: 'Split 64-bit block into L0 (left 32 bits) and R0 (right 32 bits)',
        L0: plaintextBin.substring(0, 32),
        R0: plaintextBin.substring(32)
    });

    // Show Feistel structure for 16 rounds
    for (let round = 1; round <= 16; round++) {
        steps.push({
            step: `Round ${round}`,
            description: `L${round} = R${round - 1}, R${round} = L${round - 1} ⊕ f(R${round - 1}, K${round})`,
            operations: [
                'Expansion (32→48 bits)',
                `XOR with round key K${round}`,
                'S-box substitution (48→32 bits)',
                'P-box permutation'
            ]
        });
    }

    // Final Permutation
    steps.push({
        step: 'Final Permutation (FP)',
        description: 'Apply inverse of initial permutation'
    });

    return {
        algorithm: 'DES',
        blockSize: '64 bits',
        keySize: '56 bits (64 with parity)',
        rounds: 16,
        steps
    };
}

/**
 * S-Box Lookup Demo
 */
export function desSboxDemo(input6bit) {
    // input6bit should be 6 binary digits as string
    const row = parseInt(input6bit[0] + input6bit[5], 2); // outer bits
    const col = parseInt(input6bit.substring(1, 5), 2); // middle 4 bits

    const output = DES_SBOXES[0][row][col]; // Using S1 for demo

    return {
        input: input6bit,
        row: row,
        col: col,
        output: output,
        outputBinary: output.toString(2).padStart(4, '0')
    };
}

// ==================== AES (SIMPLIFIED EDUCATIONAL) ====================

// AES S-Box
const AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // ... (full 256-byte S-box would be here)
];

/**
 * AES Educational Demo
 * Shows the structure without full implementation
 */
export function aesDemo(plaintext, key) {
    const steps = [];

    steps.push({
        step: 'Input',
        plaintext: plaintext.substring(0, 16),
        key: key.substring(0, 16),
        description: 'AES-128 uses 128-bit (16 byte) blocks and keys'
    });

    // Key Expansion
    steps.push({
        step: 'Key Expansion',
        description: 'Expand 128-bit key into 11 round keys (44 words)',
        rounds: 10
    });

    // Initial AddRoundKey
    steps.push({
        step: 'Initial AddRoundKey',
        description: 'XOR state with first round key (K0)'
    });

    // Main rounds (1-9)
    for (let round = 1; round <= 9; round++) {
        steps.push({
            step: `Round ${round}`,
            operations: [
                { name: 'SubBytes', description: 'Replace each byte using S-box' },
                { name: 'ShiftRows', description: 'Circular left shift rows (0,1,2,3 positions)' },
                { name: 'MixColumns', description: 'Matrix multiplication in GF(2^8)' },
                { name: 'AddRoundKey', description: `XOR with round key K${round}` }
            ]
        });
    }

    // Final round (no MixColumns)
    steps.push({
        step: 'Round 10 (Final)',
        operations: [
            { name: 'SubBytes', description: 'Replace each byte using S-box' },
            { name: 'ShiftRows', description: 'Circular left shift rows' },
            { name: 'AddRoundKey', description: 'XOR with round key K10' }
        ],
        note: 'No MixColumns in final round'
    });

    return {
        algorithm: 'AES-128',
        blockSize: '128 bits',
        keySize: '128 bits',
        rounds: 10,
        steps
    };
}

/**
 * AES SubBytes Demo
 */
export function aesSubBytesDemo(byte) {
    const row = (byte >> 4) & 0x0F;
    const col = byte & 0x0F;
    const substituted = AES_SBOX[byte] || 0x63; // Default if out of range

    return {
        input: byte.toString(16).padStart(2, '0').toUpperCase(),
        row: row.toString(16).toUpperCase(),
        col: col.toString(16).toUpperCase(),
        output: substituted.toString(16).padStart(2, '0').toUpperCase()
    };
}

// ==================== HELPER ====================

function textToBinary(text) {
    return text.split('').map(c =>
        c.charCodeAt(0).toString(2).padStart(8, '0')
    ).join('');
}

// ==================== EXPORTS ====================

export const ModernCrypto = {
    // Math helpers
    extendedGCD,
    modInverseBigInt,
    eulerPhi,
    primeFactorization,
    modPow,
    // RSA
    rsaGenerateKeys,
    rsaEncrypt,
    rsaDecrypt,
    // DES
    desDemo,
    desSboxDemo,
    // AES
    aesDemo,
    aesSubBytesDemo
};
