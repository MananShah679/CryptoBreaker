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
 * Computes base^exp mod m efficiently using BigInt
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

    return { result, steps };
}

/**
 * Fast modPow without step tracking (for performance benchmarks)
 */
function modPowFast(base, exp, mod) {
    base = BigInt(base);
    exp = BigInt(exp);
    mod = BigInt(mod);
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) result = (result * base) % mod;
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}

// ==================== RSA ====================

/**
 * BigInt GCD helper
 */
function gcdBig(a, b) {
    a = a < 0n ? -a : a;
    b = b < 0n ? -b : b;
    while (b > 0n) { [a, b] = [b, a % b]; }
    return a;
}

function gcdNum(a, b) {
    return b === 0 ? a : gcdNum(b, a % b);
}

/**
 * RSA Key Generation with step-by-step output (BigInt)
 */
export function rsaGenerateKeys(p, q, e = null) {
    p = BigInt(p);
    q = BigInt(q);
    const steps = [];

    // Step 1: Calculate n
    const n = p * q;
    steps.push({ step: 1, description: 'Calculate n = p × q', formula: `n = p × q`, result: n.toString() });

    // Step 2: Calculate φ(n) = (p-1)(q-1)
    const phi = (p - 1n) * (q - 1n);
    steps.push({ step: 2, description: 'Calculate φ(n) = (p-1)(q-1)', formula: `φ(n) = (p-1)(q-1)`, result: phi.toString() });

    // Step 3: Choose e if not provided
    if (e === null || e === undefined) {
        for (const candidate of [65537n, 17n, 7n, 3n]) {
            if (gcdBig(candidate, phi) === 1n && candidate < phi) {
                e = candidate;
                break;
            }
        }
    } else {
        e = BigInt(e);
    }
    steps.push({ step: 3, description: 'Choose e (coprime with φ(n))', formula: `gcd(e, φ(n)) = 1`, result: e.toString() });

    // Step 4: Calculate d = e^(-1) mod φ(n)
    const d = modInverseBigInt(e, phi);
    steps.push({ step: 4, description: 'Calculate d = e⁻¹ mod φ(n)', formula: `d = e⁻¹ mod φ(n)`, result: d.toString() });

    // Verification
    const verification = (e * d) % phi;
    steps.push({ step: 5, description: 'Verify: e × d ≡ 1 (mod φ(n))', formula: `e × d mod φ(n) = ${verification.toString()}`, result: verification === 1n ? 'Valid ✓' : 'Invalid ✗' });

    return {
        publicKey: { e, n },
        privateKey: { d, n },
        phi,
        steps
    };
}

/**
 * RSA Encryption with step-by-step output (BigInt)
 */
export function rsaEncrypt(message, e, n) {
    message = BigInt(message);
    e = BigInt(e);
    n = BigInt(n);
    const steps = [];

    steps.push({ step: 1, description: 'Apply encryption formula', formula: `C = M^e mod n` });

    const { result: ciphertext, steps: powSteps } = modPow(message, e, n);

    steps.push({ step: 2, description: 'Modular exponentiation (square & multiply)', details: powSteps.length <= 20 ? powSteps : [{ note: `${powSteps.length} steps performed` }] });
    steps.push({ step: 3, description: 'Ciphertext', result: ciphertext.toString() });

    return { ciphertext, steps };
}

/**
 * RSA Decryption with step-by-step output (BigInt)
 */
export function rsaDecrypt(ciphertext, d, n) {
    ciphertext = BigInt(ciphertext);
    d = BigInt(d);
    n = BigInt(n);
    const steps = [];

    steps.push({ step: 1, description: 'Apply decryption formula', formula: `M = C^d mod n` });

    const { result: plaintext, steps: powSteps } = modPow(ciphertext, d, n);

    steps.push({ step: 2, description: 'Modular exponentiation (square & multiply)', details: powSteps.length <= 20 ? powSteps : [{ note: `${powSteps.length} steps performed` }] });
    steps.push({ step: 3, description: 'Plaintext', result: plaintext.toString() });

    return { plaintext, steps };
}

/**
 * RSA Digital Signature: S = M^d mod n
 */
export function rsaSign(message, d, n) {
    message = BigInt(message);
    d = BigInt(d);
    n = BigInt(n);
    const signature = modPowFast(message, d, n);
    return { signature, message };
}

/**
 * RSA Signature Verification: M' = S^e mod n, check M' === M
 */
export function rsaVerify(signature, e, n, originalMessage) {
    signature = BigInt(signature);
    e = BigInt(e);
    n = BigInt(n);
    originalMessage = BigInt(originalMessage);
    const recovered = modPowFast(signature, e, n);
    return { recovered, valid: recovered === originalMessage };
}

// ==================== RSA PERFORMANCE BENCHMARK ====================

// Pre-generated verified primes for each key size (generated via Node.js crypto.generatePrime)
const RSA_TEST_PRIMES = {
    512: {
        p: 95115077119426836882928772678701989296721754626182740138259064032779013435017n,
        q: 103232412650700238143989686021709551717537700905172340652729385369791723420121n,
        e: 65537n
    },
    1024: {
        p: 10996062631626381724218532350091265912337785671286214603482938170583041248617474295074797706702686439828575382832758097406168174252521151883855325462729743n,
        q: 12196776351779106646527103608221370602469949003177114350669308116048627310708220949648257954997477122725223542375178500644439696806634341719164327611412887n,
        e: 65537n
    },
    2048: {
        p: 147458413662848547723565422024777387413377359883978999129589374167624063974668163393182384005960284688752244204163381244597695346616897930964257397035059679268798455929431795198176104382538965277480334162800711428985129203101574384026391660251698960506650374875540839431160532104693281865861983584309922237657n,
        q: 167928580876399201822460162654688093330485883533999835234382729177193776986698882625621132749363839234823372768342812534861772254014737266026803872059800456575043882128065771871049523581090521996944876278159776879797793920731487048938761633691729738225117923339541555225561601396008723044966804150550220168691n,
        e: 65537n
    },
    4096: {
        p: 27211998747245267171600449673008990052338653793324621641566461270240089805922724897817623515201745344766873539896145911756752352680310358964829475642463945235096069913221091027572653907888636540298343638628513605024888512749775895066567386178434492418882791102649662458484078054176882687631984963886053695613895038907355128246959668702297367740829530574179638960909045086457427491372938668423715050801149889714970898599651925609273575278354829449884049005901568882433187580460682699553077257484702165294033343752648281954846545806847848418798190938541978535192394646028087406624291568547509136190930054936492865406593n,
        q: 24783959502427367343046885845234343501692937649665165723784224354885332989823140138588953393428798653337847338342392097259913836295583075334866727600569005907947619533780121614133862711667488673141421604819066696580200120857422490162986777555912338213295686939590361518116758883981783795053382300785409500939545228140360394276843282742811519109757713499403147163386878646256070407288556132728204881625771025556074849286960844694774618769969415346127598724673404933760178926540339468408897080581425729828734891633229019018351730785982331892271943669053858151276595900930266846124427441194956705268057002382567336686153n,
        e: 65537n
    }
};

/**
 * Run a full RSA performance benchmark across multiple key sizes
 * Returns timing data for keygen, encrypt, decrypt, sign, verify
 */
export function rsaPerformanceBenchmark(customParams = null) {
    const results = [];
    const keySizes = [512, 1024, 2048, 4096];
    const testMessage = 42n; // Simple test message

    for (const size of keySizes) {
        const params = (customParams && customParams.keySize === size)
            ? customParams
            : RSA_TEST_PRIMES[size];

        if (!params) continue;

        const timings = {};
        let keys, ciphertext, signature;

        // 1. Key Generation
        const t1 = performance.now();
        try {
            keys = rsaGenerateKeysFast(params.p, params.q, params.e);
            timings.keygen = performance.now() - t1;
        } catch (e) {
            timings.keygen = -1;
            results.push({ keySize: size, timings, error: 'Key generation failed: ' + e.message });
            continue;
        }

        // 2. Encryption
        const t2 = performance.now();
        ciphertext = modPowFast(testMessage, keys.e, keys.n);
        timings.encrypt = performance.now() - t2;

        // 3. Decryption
        const t3 = performance.now();
        const decrypted = modPowFast(ciphertext, keys.d, keys.n);
        timings.decrypt = performance.now() - t3;

        // 4. Signing
        const t4 = performance.now();
        signature = modPowFast(testMessage, keys.d, keys.n);
        timings.sign = performance.now() - t4;

        // 5. Verification
        const t5 = performance.now();
        const verified = modPowFast(signature, keys.e, keys.n);
        timings.verify = performance.now() - t5;

        const valid = decrypted === testMessage && verified === testMessage;

        results.push({
            keySize: size,
            timings,
            n: keys.n.toString().length + ' digits',
            valid,
            ciphertext: ciphertext.toString().substring(0, 40) + '...',
            signature: signature.toString().substring(0, 40) + '...'
        });
    }

    return results;
}

/**
 * Benchmark with custom user-provided primes
 */
export function rsaCustomBenchmark(p, q, e = 65537n) {
    p = BigInt(p);
    q = BigInt(q);
    e = BigInt(e);
    const testMessage = 42n;
    const timings = {};

    // Key Generation
    const t1 = performance.now();
    const keys = rsaGenerateKeysFast(p, q, e);
    timings.keygen = performance.now() - t1;

    // Estimate key size from n
    const nBits = keys.n.toString(2).length;
    const keySize = nBits;

    // Encryption
    const t2 = performance.now();
    const ciphertext = modPowFast(testMessage, keys.e, keys.n);
    timings.encrypt = performance.now() - t2;

    // Decryption
    const t3 = performance.now();
    const decrypted = modPowFast(ciphertext, keys.d, keys.n);
    timings.decrypt = performance.now() - t3;

    // Signing
    const t4 = performance.now();
    const signature = modPowFast(testMessage, keys.d, keys.n);
    timings.sign = performance.now() - t4;

    // Verification
    const t5 = performance.now();
    const verified = modPowFast(signature, keys.e, keys.n);
    timings.verify = performance.now() - t5;

    const valid = decrypted === testMessage && verified === testMessage;

    return {
        keySize: `~${nBits}-bit (custom)`,
        timings,
        n: keys.n.toString().length + ' digits',
        valid,
        keys: { e: keys.e.toString(), d: keys.d.toString().substring(0, 60) + '...', n: keys.n.toString().substring(0, 60) + '...' }
    };
}

/**
 * Fast key generation without step tracking
 */
function rsaGenerateKeysFast(p, q, e) {
    p = BigInt(p);
    q = BigInt(q);
    e = BigInt(e);
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const d = modInverseBigInt(e, phi);
    return { e, d, n, phi };
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
    rsaSign,
    rsaVerify,
    rsaPerformanceBenchmark,
    rsaCustomBenchmark,
    // DES
    desDemo,
    desSboxDemo,
    // AES
    aesDemo,
    aesSubBytesDemo
};
