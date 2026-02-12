/**
 * Cryptanalysis Core Module
 * Brute-force cryptanalysis for classical substitution ciphers
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

// ==================== HELPER FUNCTIONS ====================

function charToNum(c) {
    return c.charCodeAt(0) - 'A'.charCodeAt(0);
}

function numToChar(n) {
    return String.fromCharCode(((n % 26) + 26) % 26 + 'A'.charCodeAt(0));
}

function cleanText(text) {
    return text.toUpperCase().replace(/[^A-Z ]/g, '');
}

function gcd(a, b) {
    return b === 0 ? a : gcd(b, a % b);
}

function modInverse(k, mod = 26) {
    k = ((k % mod) + mod) % mod;
    for (let x = 1; x < mod; x++) {
        if ((k * x) % mod === 1) {
            return x;
        }
    }
    return null;
}

// Get all valid multiplicative keys (coprime with 26)
function getValidMultiplicativeKeys() {
    const keys = [];
    for (let k = 1; k < 26; k++) {
        if (gcd(k, 26) === 1) {
            keys.push(k);
        }
    }
    return keys;
}

// ==================== ADDITIVE CIPHER ====================

function encryptAdditive(plaintext, key) {
    return cleanText(plaintext)
        .split('')
        .map(c => c === ' ' ? ' ' : numToChar(charToNum(c) + key))
        .join('');
}

function decryptAdditive(ciphertext, key) {
    return ciphertext
        .split('')
        .map(c => c === ' ' ? ' ' : numToChar(charToNum(c) - key))
        .join('');
}

function bruteForceAdditive(ciphertext) {
    const results = [];
    const cleaned = cleanText(ciphertext);

    for (let key = 0; key < 26; key++) {
        const plaintext = decryptAdditive(cleaned, key);
        results.push({
            key: key,
            keyDisplay: `Key = ${key}`,
            plaintext: plaintext,
            score: 0
        });
    }

    return results;
}

// ==================== MULTIPLICATIVE CIPHER ====================

function encryptMultiplicative(plaintext, key) {
    if (gcd(key, 26) !== 1) {
        throw new Error('Key must be coprime with 26');
    }
    return cleanText(plaintext)
        .split('')
        .map(c => c === ' ' ? ' ' : numToChar(charToNum(c) * key))
        .join('');
}

function decryptMultiplicative(ciphertext, key) {
    const inv = modInverse(key);
    if (inv === null) return null;

    return ciphertext
        .split('')
        .map(c => c === ' ' ? ' ' : numToChar(charToNum(c) * inv))
        .join('');
}

function bruteForceMultiplicative(ciphertext) {
    const results = [];
    const cleaned = cleanText(ciphertext);
    const validKeys = getValidMultiplicativeKeys();

    for (const key of validKeys) {
        const plaintext = decryptMultiplicative(cleaned, key);
        if (plaintext) {
            results.push({
                key: key,
                keyDisplay: `Key = ${key}`,
                plaintext: plaintext,
                score: 0
            });
        }
    }

    return results;
}

// ==================== AFFINE CIPHER ====================

function encryptAffine(plaintext, a, b) {
    if (gcd(a, 26) !== 1) {
        throw new Error('a must be coprime with 26');
    }
    return cleanText(plaintext)
        .split('')
        .map(c => c === ' ' ? ' ' : numToChar(a * charToNum(c) + b))
        .join('');
}

function decryptAffine(ciphertext, a, b) {
    const invA = modInverse(a);
    if (invA === null) return null;

    return ciphertext
        .split('')
        .map(c => c === ' ' ? ' ' : numToChar(invA * (charToNum(c) - b)))
        .join('');
}

function bruteForceAffine(ciphertext) {
    const results = [];
    const cleaned = cleanText(ciphertext);
    const validAKeys = getValidMultiplicativeKeys();

    for (const a of validAKeys) {
        for (let b = 0; b < 26; b++) {
            const plaintext = decryptAffine(cleaned, a, b);
            if (plaintext) {
                results.push({
                    key: { a, b },
                    keyDisplay: `a = ${a}, b = ${b}`,
                    plaintext: plaintext,
                    score: 0
                });
            }
        }
    }

    return results;
}

// ==================== VIGENERE CIPHER ====================

function encryptVigenere(plaintext, key) {
    const cleaned = cleanText(plaintext).replace(/ /g, '');
    const keyClean = cleanText(key).replace(/ /g, '');
    if (!keyClean) throw new Error('Key cannot be empty');

    return cleaned.split('').map((c, i) => {
        const shift = charToNum(keyClean[i % keyClean.length]);
        return numToChar(charToNum(c) + shift);
    }).join('');
}

function decryptVigenere(ciphertext, key) {
    const keyClean = cleanText(key).replace(/ /g, '');
    if (!keyClean) return null;

    return ciphertext.replace(/ /g, '').split('').map((c, i) => {
        const shift = charToNum(keyClean[i % keyClean.length]);
        return numToChar(charToNum(c) - shift);
    }).join('');
}

// Index of Coincidence calculation
function calculateIC(text) {
    const cleaned = text.replace(/[^A-Z]/g, '');
    const n = cleaned.length;
    if (n <= 1) return 0;

    const freq = {};
    for (const c of cleaned) {
        freq[c] = (freq[c] || 0) + 1;
    }

    let sum = 0;
    for (const c in freq) {
        sum += freq[c] * (freq[c] - 1);
    }

    return sum / (n * (n - 1));
}

// Estimate key length using IC
function estimateVigenereKeyLength(ciphertext, maxLen = 15) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const results = [];

    for (let keyLen = 1; keyLen <= maxLen; keyLen++) {
        let avgIC = 0;
        for (let i = 0; i < keyLen; i++) {
            let substr = '';
            for (let j = i; j < cleaned.length; j += keyLen) {
                substr += cleaned[j];
            }
            avgIC += calculateIC(substr);
        }
        avgIC /= keyLen;
        results.push({ keyLen, ic: avgIC });
    }

    // English IC is ~0.067, random is ~0.038
    results.sort((a, b) => Math.abs(a.ic - 0.067) - Math.abs(b.ic - 0.067));
    return results.slice(0, 5).map(r => r.keyLen);
}

function bruteForceVigenere(ciphertext) {
    const cleaned = cleanText(ciphertext).replace(/ /g, '');
    const results = [];
    const keyLengths = estimateVigenereKeyLength(cleaned);

    for (const keyLen of keyLengths) {
        // Try to find key by frequency analysis on each position
        let key = '';
        for (let i = 0; i < keyLen; i++) {
            let substr = '';
            for (let j = i; j < cleaned.length; j += keyLen) {
                substr += cleaned[j];
            }
            // Find most likely shift (E is most common)
            let bestShift = 0;
            let bestScore = -1;
            for (let shift = 0; shift < 26; shift++) {
                const decrypted = substr.split('').map(c => numToChar(charToNum(c) - shift)).join('');
                const eCount = (decrypted.match(/E/g) || []).length;
                if (eCount > bestScore) {
                    bestScore = eCount;
                    bestShift = shift;
                }
            }
            key += numToChar(bestShift);
        }

        const plaintext = decryptVigenere(cleaned, key);
        results.push({
            key: key,
            keyDisplay: `Key = "${key}" (len=${keyLen})`,
            plaintext: plaintext,
            score: 0
        });
    }

    return results;
}

// ==================== PLAYFAIR CIPHER ====================

function generatePlayfairMatrix(key) {
    const keyClean = cleanText(key).replace(/ /g, '').replace(/J/g, 'I');
    const seen = new Set();
    const matrix = [];

    for (const c of keyClean + ALPHABET.replace('J', '')) {
        if (!seen.has(c)) {
            seen.add(c);
            matrix.push(c);
        }
    }

    return matrix;
}

function findInMatrix(matrix, char) {
    const idx = matrix.indexOf(char === 'J' ? 'I' : char);
    return { row: Math.floor(idx / 5), col: idx % 5 };
}

function encryptPlayfair(plaintext, key) {
    const matrix = generatePlayfairMatrix(key);
    let cleaned = cleanText(plaintext).replace(/ /g, '').replace(/J/g, 'I');

    // Prepare digraphs
    const digraphs = [];
    let i = 0;
    while (i < cleaned.length) {
        let a = cleaned[i];
        let b = cleaned[i + 1] || 'X';
        if (a === b) {
            b = 'X';
            i++;
        } else {
            i += 2;
        }
        digraphs.push([a, b]);
    }

    return digraphs.map(([a, b]) => {
        const posA = findInMatrix(matrix, a);
        const posB = findInMatrix(matrix, b);

        if (posA.row === posB.row) {
            return matrix[posA.row * 5 + (posA.col + 1) % 5] +
                matrix[posB.row * 5 + (posB.col + 1) % 5];
        } else if (posA.col === posB.col) {
            return matrix[((posA.row + 1) % 5) * 5 + posA.col] +
                matrix[((posB.row + 1) % 5) * 5 + posB.col];
        } else {
            return matrix[posA.row * 5 + posB.col] +
                matrix[posB.row * 5 + posA.col];
        }
    }).join('');
}

function decryptPlayfair(ciphertext, key) {
    const matrix = generatePlayfairMatrix(key);
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');

    const digraphs = [];
    for (let i = 0; i < cleaned.length; i += 2) {
        digraphs.push([cleaned[i], cleaned[i + 1] || 'X']);
    }

    return digraphs.map(([a, b]) => {
        const posA = findInMatrix(matrix, a);
        const posB = findInMatrix(matrix, b);

        if (posA.row === posB.row) {
            return matrix[posA.row * 5 + (posA.col + 4) % 5] +
                matrix[posB.row * 5 + (posB.col + 4) % 5];
        } else if (posA.col === posB.col) {
            return matrix[((posA.row + 4) % 5) * 5 + posA.col] +
                matrix[((posB.row + 4) % 5) * 5 + posB.col];
        } else {
            return matrix[posA.row * 5 + posB.col] +
                matrix[posB.row * 5 + posA.col];
        }
    }).join('');
}

// Common Playfair keys for dictionary attack
const COMMON_PLAYFAIR_KEYS = [
    'KEYWORD', 'SECRET', 'CIPHER', 'PLAYFAIR', 'MONARCHY', 'SECURITY',
    'CRYPTOGRAPHY', 'HIDDEN', 'MESSAGE', 'PASSWORD', 'EXAMPLE', 'CHARLES'
];

function bruteForcePlayfair(ciphertext) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const results = [];

    for (const key of COMMON_PLAYFAIR_KEYS) {
        const plaintext = decryptPlayfair(cleaned, key);
        results.push({
            key: key,
            keyDisplay: `Key = "${key}"`,
            plaintext: plaintext,
            score: 0
        });
    }

    return results;
}

// ==================== HILL CIPHER (2x2) ====================

function matrixMult2x2(matrix, vec, mod = 26) {
    return [
        (matrix[0][0] * vec[0] + matrix[0][1] * vec[1]) % mod,
        (matrix[1][0] * vec[0] + matrix[1][1] * vec[1]) % mod
    ].map(x => ((x % mod) + mod) % mod);
}

function matrixInverse2x2(matrix, mod = 26) {
    const det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % mod;
    const detPos = ((det % mod) + mod) % mod;
    const detInv = modInverse(detPos, mod);

    if (detInv === null) return null;

    return [
        [(matrix[1][1] * detInv) % mod, (-matrix[0][1] * detInv % mod + mod) % mod],
        [(-matrix[1][0] * detInv % mod + mod) % mod, (matrix[0][0] * detInv) % mod]
    ].map(row => row.map(x => ((x % mod) + mod) % mod));
}

function encryptHill(plaintext, matrix) {
    const cleaned = cleanText(plaintext).replace(/ /g, '');
    const padded = cleaned.length % 2 === 0 ? cleaned : cleaned + 'X';

    let result = '';
    for (let i = 0; i < padded.length; i += 2) {
        const vec = [charToNum(padded[i]), charToNum(padded[i + 1])];
        const encrypted = matrixMult2x2(matrix, vec);
        result += numToChar(encrypted[0]) + numToChar(encrypted[1]);
    }

    return result;
}

function decryptHill(ciphertext, matrix) {
    const invMatrix = matrixInverse2x2(matrix);
    if (!invMatrix) return null;

    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    let result = '';

    for (let i = 0; i < cleaned.length; i += 2) {
        const vec = [charToNum(cleaned[i]), charToNum(cleaned[i + 1] || 'X')];
        const decrypted = matrixMult2x2(invMatrix, vec);
        result += numToChar(decrypted[0]) + numToChar(decrypted[1]);
    }

    return result;
}

function bruteForceHill(ciphertext) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const results = [];
    const validKeys = getValidMultiplicativeKeys();

    // Try common 2x2 matrices with invertible determinants
    for (const a of validKeys.slice(0, 6)) {
        for (const d of validKeys.slice(0, 6)) {
            for (let b = 0; b < 10; b++) {
                for (let c = 0; c < 10; c++) {
                    const matrix = [[a, b], [c, d]];
                    const det = (a * d - b * c) % 26;
                    if (gcd(Math.abs(det), 26) !== 1) continue;

                    const plaintext = decryptHill(cleaned, matrix);
                    if (plaintext) {
                        results.push({
                            key: matrix,
                            keyDisplay: `[[${a},${b}],[${c},${d}]]`,
                            plaintext: plaintext,
                            score: 0
                        });
                    }

                    if (results.length >= 100) break;
                }
                if (results.length >= 100) break;
            }
            if (results.length >= 100) break;
        }
        if (results.length >= 100) break;
    }

    return results;
}

// ==================== RAIL FENCE CIPHER ====================

function encryptRailFence(plaintext, rails) {
    const cleaned = cleanText(plaintext).replace(/ /g, '');
    if (rails < 2) return cleaned;

    const fence = Array(rails).fill('').map(() => []);
    let rail = 0;
    let direction = 1;

    for (const char of cleaned) {
        fence[rail].push(char);
        rail += direction;
        if (rail === 0 || rail === rails - 1) direction *= -1;
    }

    return fence.flat().join('');
}

function decryptRailFence(ciphertext, rails) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const n = cleaned.length;
    if (rails < 2) return cleaned;

    // Calculate rail lengths
    const railLens = Array(rails).fill(0);
    let rail = 0;
    let direction = 1;

    for (let i = 0; i < n; i++) {
        railLens[rail]++;
        rail += direction;
        if (rail === 0 || rail === rails - 1) direction *= -1;
    }

    // Fill rails
    const fence = [];
    let idx = 0;
    for (let r = 0; r < rails; r++) {
        fence.push(cleaned.slice(idx, idx + railLens[r]).split(''));
        idx += railLens[r];
    }

    // Read off
    let result = '';
    rail = 0;
    direction = 1;
    const railIdx = Array(rails).fill(0);

    for (let i = 0; i < n; i++) {
        result += fence[rail][railIdx[rail]++];
        rail += direction;
        if (rail === 0 || rail === rails - 1) direction *= -1;
    }

    return result;
}

function bruteForceRailFence(ciphertext) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const results = [];

    for (let rails = 2; rails <= Math.min(20, cleaned.length); rails++) {
        const plaintext = decryptRailFence(cleaned, rails);
        results.push({
            key: rails,
            keyDisplay: `Rails = ${rails}`,
            plaintext: plaintext,
            score: 0
        });
    }

    return results;
}

// ==================== COLUMNAR TRANSPOSITION ====================

function encryptColumnar(plaintext, key) {
    const cleaned = cleanText(plaintext).replace(/ /g, '');
    const keyClean = cleanText(key).replace(/ /g, '');
    const numCols = keyClean.length;
    const numRows = Math.ceil(cleaned.length / numCols);

    // Pad with X
    const padded = cleaned.padEnd(numRows * numCols, 'X');

    // Create grid
    const grid = [];
    for (let i = 0; i < numRows; i++) {
        grid.push(padded.slice(i * numCols, (i + 1) * numCols));
    }

    // Get column order from key
    const order = keyClean.split('').map((c, i) => ({ c, i }))
        .sort((a, b) => a.c.localeCompare(b.c))
        .map(x => x.i);

    // Read columns in order
    return order.map(col => grid.map(row => row[col]).join('')).join('');
}

function decryptColumnar(ciphertext, key) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const keyClean = cleanText(key).replace(/ /g, '');
    const numCols = keyClean.length;
    const numRows = Math.ceil(cleaned.length / numCols);

    // Get column order
    const order = keyClean.split('').map((c, i) => ({ c, i }))
        .sort((a, b) => a.c.localeCompare(b.c))
        .map(x => x.i);

    // Fill columns
    const cols = Array(numCols).fill('');
    let idx = 0;
    for (const col of order) {
        cols[col] = cleaned.slice(idx, idx + numRows);
        idx += numRows;
    }

    // Read rows
    let result = '';
    for (let r = 0; r < numRows; r++) {
        for (let c = 0; c < numCols; c++) {
            if (cols[c][r]) result += cols[c][r];
        }
    }

    return result;
}

const COMMON_COLUMNAR_KEYS = [
    'KEY', 'SECRET', 'CIPHER', 'CODE', 'CRYPTO', 'HIDDEN', 'SECURE',
    'PASSWORD', 'KEYWORD', 'ZEBRA', 'GERMAN', 'ENCODE', 'DECODE'
];

function bruteForceColumnar(ciphertext) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const results = [];

    for (const key of COMMON_COLUMNAR_KEYS) {
        if (key.length > cleaned.length) continue;
        const plaintext = decryptColumnar(cleaned, key);
        results.push({
            key: key,
            keyDisplay: `Key = "${key}"`,
            plaintext: plaintext,
            score: 0
        });
    }

    return results;
}

// ==================== DOUBLE TRANSPOSITION ====================

function encryptDoubleTransposition(plaintext, key1, key2) {
    const first = encryptColumnar(plaintext, key1);
    return encryptColumnar(first, key2);
}

function decryptDoubleTransposition(ciphertext, key1, key2) {
    const first = decryptColumnar(ciphertext, key2);
    return decryptColumnar(first, key1);
}

function bruteForceDoubleTransposition(ciphertext) {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const results = [];

    // Try common key combinations
    for (const key1 of COMMON_COLUMNAR_KEYS.slice(0, 5)) {
        for (const key2 of COMMON_COLUMNAR_KEYS.slice(0, 5)) {
            if (key1.length > cleaned.length || key2.length > cleaned.length) continue;
            const plaintext = decryptDoubleTransposition(cleaned, key1, key2);
            results.push({
                key: { key1, key2 },
                keyDisplay: `Keys = "${key1}", "${key2}"`,
                plaintext: plaintext,
                score: 0
            });
        }
    }

    return results;
}

// ==================== FLEXIBLE PRODUCT CIPHER (Any Substitution + Any Transposition) ====================

// Common keys for brute force
const COMMON_VIGENERE_KEYS = [
    'KEY', 'SECRET', 'CIPHER', 'LEMON', 'SECURE', 'CRYPTO', 'HIDDEN',
    'PASSWORD', 'KEYWORD', 'ENCODE', 'DECODE', 'ALPHA', 'BETA'
];

// Dispatcher for substitution encryption
function applySubstitutionEncrypt(text, type, key) {
    switch (type) {
        case 'additive': return encryptAdditive(text, key.k);
        case 'multiplicative': return encryptMultiplicative(text, key.k);
        case 'affine': return encryptAffine(text, key.a, key.b);
        case 'vigenere': return encryptVigenere(text, key.word);
        case 'playfair': return encryptPlayfair(text, key.word);
        case 'hill': return encryptHill(text, key.matrix);
        default: return text;
    }
}

// Dispatcher for substitution decryption
function applySubstitutionDecrypt(text, type, key) {
    switch (type) {
        case 'additive': return decryptAdditive(text, key.k);
        case 'multiplicative': return decryptMultiplicative(text, key.k);
        case 'affine': return decryptAffine(text, key.a, key.b);
        case 'vigenere': return decryptVigenere(text, key.word);
        case 'playfair': return decryptPlayfair(text, key.word);
        case 'hill': return decryptHill(text, key.matrix);
        default: return text;
    }
}

// Dispatcher for transposition encryption
function applyTranspositionEncrypt(text, type, key) {
    switch (type) {
        case 'railfence': return encryptRailFence(text, key.rails);
        case 'columnar': return encryptColumnar(text, key.word);
        case 'double': return encryptDoubleTransposition(text, key.word1, key.word2);
        default: return text;
    }
}

// Dispatcher for transposition decryption
function applyTranspositionDecrypt(text, type, key) {
    switch (type) {
        case 'railfence': return decryptRailFence(text, key.rails);
        case 'columnar': return decryptColumnar(text, key.word);
        case 'double': return decryptDoubleTransposition(text, key.word1, key.word2);
        default: return text;
    }
}

function encryptProductCipherFlexible(plaintext, subType, subKey, transType, transKey) {
    // Step 1: Apply substitution cipher
    const afterSubstitution = applySubstitutionEncrypt(plaintext, subType, subKey);
    // Step 2: Apply transposition cipher
    const finalCipher = applyTranspositionEncrypt(afterSubstitution, transType, transKey);
    return { afterSubstitution, finalCipher };
}

function decryptProductCipherFlexible(ciphertext, subType, subKey, transType, transKey) {
    // Step 1: Reverse transposition cipher
    const afterTransposition = applyTranspositionDecrypt(ciphertext, transType, transKey);
    // Step 2: Reverse substitution cipher
    const plaintext = applySubstitutionDecrypt(afterTransposition, subType, subKey);
    return { afterTransposition, plaintext };
}

// Legacy fixed functions for backwards compatibility
function encryptProductCipher(plaintext, vigKey, transKey) {
    return encryptProductCipherFlexible(plaintext, 'vigenere', { word: vigKey }, 'columnar', { word: transKey });
}

function decryptProductCipher(ciphertext, vigKey, transKey) {
    return decryptProductCipherFlexible(ciphertext, 'vigenere', { word: vigKey }, 'columnar', { word: transKey });
}

function bruteForceProductCipher(ciphertext, subType = 'vigenere', transType = 'columnar') {
    const cleaned = ciphertext.replace(/[^A-Z]/g, '');
    const results = [];

    // Try common key combinations based on cipher types
    const subKeys = subType === 'vigenere' ? COMMON_VIGENERE_KEYS.slice(0, 5) :
        subType === 'additive' ? Array.from({ length: 26 }, (_, i) => i) :
            COMMON_VIGENERE_KEYS.slice(0, 5);

    const transKeys = transType === 'columnar' ? COMMON_COLUMNAR_KEYS.slice(0, 5) :
        transType === 'railfence' ? [2, 3, 4, 5, 6] :
            COMMON_COLUMNAR_KEYS.slice(0, 5);

    for (const sk of subKeys) {
        for (const tk of transKeys) {
            try {
                let subKey, transKey, keyDisplay;

                // Build key objects based on cipher type
                if (subType === 'vigenere' || subType === 'playfair') {
                    subKey = { word: sk };
                } else if (subType === 'additive' || subType === 'multiplicative') {
                    subKey = { k: sk };
                } else {
                    subKey = { word: sk };
                }

                if (transType === 'railfence') {
                    transKey = { rails: tk };
                    keyDisplay = `Sub="${sk}", Rails=${tk}`;
                } else {
                    transKey = { word: tk };
                    keyDisplay = `Sub="${sk}", Trans="${tk}"`;
                }

                const { plaintext } = decryptProductCipherFlexible(cleaned, subType, subKey, transType, transKey);
                results.push({
                    key: { subKey: sk, transKey: tk },
                    keyDisplay: keyDisplay,
                    plaintext: plaintext,
                    score: 0
                });
            } catch (e) {
                // Skip invalid key combinations
            }
        }
    }

    return results;
}

// ==================== AUTOKEY CIPHER ====================

function encryptAutokey(plaintext, initialKey) {
    const text = cleanText(plaintext).replace(/ /g, '');
    let result = '';
    let keyStream = [initialKey]; // Start with numeric key

    for (let i = 0; i < text.length; i++) {
        const p = charToNum(text[i]);
        const k = i === 0 ? initialKey : charToNum(text[i - 1]);
        if (i > 0) keyStream.push(charToNum(text[i - 1]));
        result += numToChar((p + (i === 0 ? initialKey : charToNum(text[i - 1]))) % 26);
    }

    return { ciphertext: result, keyStream };
}

function decryptAutokey(ciphertext, initialKey) {
    const text = cleanText(ciphertext).replace(/ /g, '');
    let result = '';
    let keyStream = [initialKey];

    for (let i = 0; i < text.length; i++) {
        const c = charToNum(text[i]);
        const k = i === 0 ? initialKey : charToNum(result[i - 1]);
        if (i > 0) keyStream.push(charToNum(result[i - 1]));
        result += numToChar((c - (i === 0 ? initialKey : charToNum(result[i - 1])) + 26) % 26);
    }

    return { plaintext: result, keyStream };
}

// ==================== SIMPLE MONOALPHABETIC CIPHER ====================

function generateMonoalphabeticKey(keyword) {
    const kw = cleanText(keyword).replace(/ /g, '');
    let key = '';
    const used = new Set();

    // Add keyword letters (no duplicates)
    for (const c of kw) {
        if (!used.has(c)) {
            key += c;
            used.add(c);
        }
    }

    // Add remaining alphabet letters
    for (const c of ALPHABET) {
        if (!used.has(c)) {
            key += c;
        }
    }

    return key;
}

function encryptMonoalphabetic(plaintext, keyAlphabet) {
    const text = cleanText(plaintext);
    let result = '';

    for (const c of text) {
        if (c === ' ') {
            result += ' ';
        } else {
            result += keyAlphabet[charToNum(c)];
        }
    }

    return result;
}

function decryptMonoalphabetic(ciphertext, keyAlphabet) {
    const text = cleanText(ciphertext);
    let result = '';

    for (const c of text) {
        if (c === ' ') {
            result += ' ';
        } else {
            result += ALPHABET[keyAlphabet.indexOf(c)];
        }
    }

    return result;
}

// ==================== VERNAM / ONE-TIME PAD ====================

function encryptVernam(plaintext, key) {
    const text = cleanText(plaintext).replace(/ /g, '');
    const keyText = cleanText(key).replace(/ /g, '');

    if (keyText.length < text.length) {
        throw new Error('Key must be at least as long as plaintext');
    }

    let result = '';
    const steps = [];

    for (let i = 0; i < text.length; i++) {
        const p = charToNum(text[i]);
        const k = charToNum(keyText[i]);
        const c = (p + k) % 26; // Mod-26 addition
        result += numToChar(c);
        steps.push({ plain: text[i], key: keyText[i], pNum: p, kNum: k, sum: c, cipher: numToChar(c) });
    }

    return { ciphertext: result, steps };
}

function decryptVernam(ciphertext, key) {
    const text = cleanText(ciphertext).replace(/ /g, '');
    const keyText = cleanText(key).replace(/ /g, '');

    if (keyText.length < text.length) {
        throw new Error('Key must be at least as long as ciphertext');
    }

    let result = '';
    const steps = [];

    for (let i = 0; i < text.length; i++) {
        const c = charToNum(text[i]);
        const k = charToNum(keyText[i]);
        const p = ((c - k) % 26 + 26) % 26; // Mod-26 subtraction
        result += numToChar(p);
        steps.push({ cipher: text[i], key: keyText[i], cNum: c, kNum: k, diff: p, plain: numToChar(p) });
    }

    return { plaintext: result, steps };
}

// ==================== SIMPLE (KEYLESS) TRANSPOSITION ====================

function encryptSimpleTransposition(plaintext, numColumns) {
    const text = cleanText(plaintext).replace(/ /g, '');
    const rows = Math.ceil(text.length / numColumns);

    // Pad with X if needed
    const padded = text.padEnd(rows * numColumns, 'X');

    // Write in rows, read by columns
    let result = '';
    for (let col = 0; col < numColumns; col++) {
        for (let row = 0; row < rows; row++) {
            result += padded[row * numColumns + col];
        }
    }

    return result;
}

function decryptSimpleTransposition(ciphertext, numColumns) {
    const text = cleanText(ciphertext).replace(/ /g, '');
    const rows = Math.ceil(text.length / numColumns);

    // Read by columns, write in rows
    let result = '';
    for (let row = 0; row < rows; row++) {
        for (let col = 0; col < numColumns; col++) {
            const idx = col * rows + row;
            if (idx < text.length) {
                result += text[idx];
            }
        }
    }

    return result;
}

function bruteForceSimpleTransposition(ciphertext) {
    const results = [];
    const text = cleanText(ciphertext).replace(/ /g, '');

    // Try different column counts
    for (let cols = 2; cols <= Math.min(10, text.length); cols++) {
        if (text.length % cols === 0 || text.length > cols) {
            const decrypted = decryptSimpleTransposition(text, cols);
            results.push({
                key: cols,
                keyDisplay: `Columns = ${cols}`,
                plaintext: decrypted,
                score: 0
            });
        }
    }

    return results;
}

// ==================== AUTOKEY BRUTE FORCE ====================

function bruteForceAutokey(ciphertext) {
    const cleaned = cleanText(ciphertext).replace(/ /g, '');
    const results = [];

    for (let key = 0; key < 26; key++) {
        const { plaintext } = decryptAutokey(cleaned, key);
        results.push({
            key: key,
            keyDisplay: `Initial Key = ${key}`,
            plaintext: plaintext,
            score: 0
        });
    }

    return results;
}

// ==================== EXPORTS ====================

export const CryptoEngine = {
    cleanText,
    getValidMultiplicativeKeys,
    // Additive
    encryptAdditive,
    decryptAdditive,
    bruteForceAdditive,
    // Multiplicative
    encryptMultiplicative,
    decryptMultiplicative,
    bruteForceMultiplicative,
    // Affine
    encryptAffine,
    decryptAffine,
    bruteForceAffine,
    // Vigenere
    encryptVigenere,
    decryptVigenere,
    bruteForceVigenere,
    // Playfair
    encryptPlayfair,
    decryptPlayfair,
    bruteForcePlayfair,
    // Hill
    encryptHill,
    decryptHill,
    bruteForceHill,
    // Rail Fence
    encryptRailFence,
    decryptRailFence,
    bruteForceRailFence,
    // Columnar
    encryptColumnar,
    decryptColumnar,
    bruteForceColumnar,
    // Double Transposition
    encryptDoubleTransposition,
    decryptDoubleTransposition,
    bruteForceDoubleTransposition,
    // Product Cipher
    encryptProductCipher,
    decryptProductCipher,
    bruteForceProductCipher,
    // Flexible Product Cipher
    encryptProductCipherFlexible,
    decryptProductCipherFlexible,
    // Autokey
    encryptAutokey,
    decryptAutokey,
    // Monoalphabetic
    generateMonoalphabeticKey,
    encryptMonoalphabetic,
    decryptMonoalphabetic,
    // Vernam (One-Time Pad)
    encryptVernam,
    decryptVernam,
    // Simple Transposition
    encryptSimpleTransposition,
    decryptSimpleTransposition,
    bruteForceSimpleTransposition,
    // Autokey Brute Force
    bruteForceAutokey
};

