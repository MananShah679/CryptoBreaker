/**
 * Automated test script for all cipher implementations
 * Run with: node test_ciphers.mjs
 */

import { CryptoEngine } from './src/lib/crypto.js';
import { ModernCrypto } from './src/lib/modern.js';

let pass = 0;
let fail = 0;

function assert(cond, name, details = '') {
    if (cond) {
        console.log(`  ✅ ${name}`);
        pass++;
    } else {
        console.log(`  ❌ ${name} ${details}`);
        fail++;
    }
}

// ======================== CLASSICAL CIPHERS ========================

console.log('\n=== ADDITIVE (Caesar) CIPHER ===');
{
    const enc = CryptoEngine.encryptAdditive('HELLOWORLD', 3);
    assert(enc === 'KHOORZRUOG', 'Encrypt HELLO+3', `got "${enc}"`);
    const dec = CryptoEngine.decryptAdditive(enc, 3);
    assert(dec === 'HELLOWORLD', 'Decrypt round-trip', `got "${dec}"`);
    const bf = CryptoEngine.bruteForceAdditive(enc);
    assert(bf.length === 26, 'Brute-force returns 26 results');
    assert(bf[3].plaintext === 'HELLOWORLD', 'Brute-force key=3 matches', `got "${bf[3].plaintext}"`);
}

console.log('\n=== MULTIPLICATIVE CIPHER ===');
{
    const enc = CryptoEngine.encryptMultiplicative('HELLOWORLD', 7);
    const dec = CryptoEngine.decryptMultiplicative(enc, 7);
    assert(dec === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${dec}"`);
    const bf = CryptoEngine.bruteForceMultiplicative(enc);
    assert(bf.length > 0, 'Brute-force returns results');
    const match = bf.find(r => r.plaintext === 'HELLOWORLD');
    assert(!!match, 'Brute-force finds correct plaintext');
}

console.log('\n=== AFFINE CIPHER ===');
{
    const enc = CryptoEngine.encryptAffine('HELLOWORLD', 5, 8);
    const dec = CryptoEngine.decryptAffine(enc, 5, 8);
    assert(dec === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${dec}"`);
    const bf = CryptoEngine.bruteForceAffine(enc);
    assert(bf.length > 0, 'Brute-force returns results');
    const match = bf.find(r => r.plaintext === 'HELLOWORLD');
    assert(!!match, 'Brute-force finds correct plaintext');
}

console.log('\n=== VIGENÈRE CIPHER ===');
{
    const enc = CryptoEngine.encryptVigenere('HELLOWORLD', 'LEMON');
    const dec = CryptoEngine.decryptVigenere(enc, 'LEMON');
    assert(dec === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${dec}"`);
    const enc2 = CryptoEngine.encryptVigenere('ATTACKATDAWN', 'LEMON');
    assert(enc2 === 'LXFOPVEFRNHR', 'Known vector: ATTACKATDAWN+LEMON', `got "${enc2}"`);
    const dec2 = CryptoEngine.decryptVigenere(enc2, 'LEMON');
    assert(dec2 === 'ATTACKATDAWN', 'Known vector decrypt', `got "${dec2}"`);
}

console.log('\n=== PLAYFAIR CIPHER ===');
{
    const enc = CryptoEngine.encryptPlayfair('HELLOWORLD', 'MONARCHY');
    const dec = CryptoEngine.decryptPlayfair(enc, 'MONARCHY');
    assert(dec.startsWith('HE'), 'Encrypt→Decrypt preserves start', `got "${dec}"`);
}

console.log('\n=== HILL CIPHER (2×2) ===');
{
    const matrix = [[3, 3], [2, 5]];
    const enc = CryptoEngine.encryptHill('HELLOWORLD', matrix);
    const dec = CryptoEngine.decryptHill(enc, matrix);
    assert(dec === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${dec}"`);
}

console.log('\n=== RAIL FENCE CIPHER ===');
{
    const enc = CryptoEngine.encryptRailFence('HELLOWORLD', 3);
    const dec = CryptoEngine.decryptRailFence(enc, 3);
    assert(dec === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${dec}"`);
    const bf = CryptoEngine.bruteForceRailFence(enc);
    assert(bf.length > 0, 'Brute-force returns results');
}

console.log('\n=== COLUMNAR TRANSPOSITION ===');
{
    const enc = CryptoEngine.encryptColumnar('HELLOWORLD', 'ZEBRA');
    const dec = CryptoEngine.decryptColumnar(enc, 'ZEBRA');
    assert(dec.startsWith('HELLOWORLD'), 'Encrypt→Decrypt round-trip', `got "${dec}"`);
}

console.log('\n=== DOUBLE TRANSPOSITION ===');
{
    const enc = CryptoEngine.encryptDoubleTransposition('HELLOWORLD', 'KEY', 'SECRET');
    const dec = CryptoEngine.decryptDoubleTransposition(enc, 'KEY', 'SECRET');
    assert(dec.startsWith('HELLOWORLD'), 'Encrypt→Decrypt round-trip', `got "${dec}"`);
}

console.log('\n=== PRODUCT CIPHER (Flexible) ===');
{
    const { finalCipher } = CryptoEngine.encryptProductCipherFlexible(
        'HELLOWORLD', 'vigenere', { word: 'KEY' }, 'columnar', { word: 'SECRET' }
    );
    const { plaintext } = CryptoEngine.decryptProductCipherFlexible(
        finalCipher, 'vigenere', { word: 'KEY' }, 'columnar', { word: 'SECRET' }
    );
    assert(plaintext.startsWith('HELLOWORLD'), 'Encrypt→Decrypt round-trip', `got "${plaintext}"`);
}

console.log('\n=== AUTOKEY CIPHER ===');
{
    const { ciphertext } = CryptoEngine.encryptAutokey('HELLOWORLD', 7);
    const { plaintext } = CryptoEngine.decryptAutokey(ciphertext, 7);
    assert(plaintext === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${plaintext}"`);
    const bf = CryptoEngine.bruteForceAutokey(ciphertext);
    assert(bf.length === 26, 'Brute-force returns 26 results');
    const match = bf.find(r => r.plaintext === 'HELLOWORLD');
    assert(!!match, 'Brute-force finds correct plaintext');
}

console.log('\n=== MONOALPHABETIC CIPHER ===');
{
    const keyAlpha = CryptoEngine.generateMonoalphabeticKey('SECRET');
    assert(keyAlpha.length === 26, 'Key alphabet is 26 chars');
    const enc = CryptoEngine.encryptMonoalphabetic('HELLOWORLD', keyAlpha);
    const dec = CryptoEngine.decryptMonoalphabetic(enc, keyAlpha);
    assert(dec === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${dec}"`);
}

console.log('\n=== VERNAM (OTP) CIPHER ===');
{
    const { ciphertext } = CryptoEngine.encryptVernam('HELLOWORLD', 'XMCKLDOTQP');
    const { plaintext } = CryptoEngine.decryptVernam(ciphertext, 'XMCKLDOTQP');
    assert(plaintext === 'HELLOWORLD', 'Encrypt→Decrypt round-trip', `got "${plaintext}"`);
    assert(/^[A-Z]+$/.test(ciphertext), 'Ciphertext is all A-Z', `got "${ciphertext}"`);
    // Additional test: verify mod-26 arithmetic
    const { ciphertext: c2 } = CryptoEngine.encryptVernam('ZZZ', 'AAA');
    assert(c2 === 'ZZZ', 'Z+A=Z (mod-26 addition)', `got "${c2}"`);
    const { ciphertext: c3 } = CryptoEngine.encryptVernam('AAA', 'BBB');
    assert(c3 === 'BBB', 'A+B=B (mod-26 addition)', `got "${c3}"`);
}

console.log('\n=== SIMPLE (KEYLESS) TRANSPOSITION ===');
{
    const enc = CryptoEngine.encryptSimpleTransposition('HELLOWORLD', 4);
    const dec = CryptoEngine.decryptSimpleTransposition(enc, 4);
    assert(dec.startsWith('HELLOWORLD'), 'Encrypt→Decrypt round-trip', `got "${dec}"`);
    const bf = CryptoEngine.bruteForceSimpleTransposition(enc);
    assert(bf.length > 0, 'Brute-force returns results');
    assert(bf[0].keyDisplay !== undefined, 'Has keyDisplay field');
    assert(bf[0].score !== undefined, 'Has score field');
}

// ======================== MODERN CIPHERS ========================

console.log('\n=== RSA ===');
{
    // Test with p=7, q=17 — standard textbook example
    const keys = ModernCrypto.rsaGenerateKeys(7, 17);
    assert(keys.publicKey.n === 119, 'n = p*q = 119', `got n=${keys.publicKey.n}`);
    assert(keys.phi === 96, 'φ(n) = (p-1)(q-1) = 96', `got φ=${keys.phi}`);
    assert(keys.publicKey.e !== undefined, 'e is computed');
    assert(keys.privateKey.d !== undefined, 'd is computed');

    // Verify e*d ≡ 1 mod φ(n)
    const edMod = (keys.publicKey.e * keys.privateKey.d) % keys.phi;
    assert(edMod === 1, `e*d mod φ(n) = 1`, `got ${edMod}`);

    // Encrypt and decrypt
    const { ciphertext } = ModernCrypto.rsaEncrypt(19, keys.publicKey.e, keys.publicKey.n);
    const { plaintext } = ModernCrypto.rsaDecrypt(ciphertext, keys.privateKey.d, keys.privateKey.n);
    assert(plaintext === 19, 'RSA encrypt→decrypt M=19', `got ${plaintext}`);

    // Test with p=11, q=13, e=7
    const keys2 = ModernCrypto.rsaGenerateKeys(11, 13, 7);
    assert(keys2.publicKey.n === 143, 'n = 11*13 = 143', `got n=${keys2.publicKey.n}`);
    assert(keys2.phi === 120, 'φ(143) = 120', `got φ=${keys2.phi}`);
    assert(keys2.publicKey.e === 7, 'e = 7', `got e=${keys2.publicKey.e}`);
    const { ciphertext: c2 } = ModernCrypto.rsaEncrypt(9, 7, 143);
    const { plaintext: p2 } = ModernCrypto.rsaDecrypt(c2, keys2.privateKey.d, 143);
    assert(p2 === 9, 'RSA encrypt→decrypt M=9 (p=11,q=13,e=7)', `got ${p2}`);

    // Test with larger primes: p=61, q=53, e=17
    const keys3 = ModernCrypto.rsaGenerateKeys(61, 53, 17);
    assert(keys3.publicKey.n === 3233, 'n = 61*53 = 3233', `got n=${keys3.publicKey.n}`);
    assert(keys3.phi === 3120, 'φ(3233) = 3120', `got φ=${keys3.phi}`);
    const ed3 = (keys3.publicKey.e * keys3.privateKey.d) % keys3.phi;
    assert(ed3 === 1, `e*d mod φ = 1 (larger primes)`, `got ${ed3}`);
    const { ciphertext: c3 } = ModernCrypto.rsaEncrypt(65, 17, 3233);
    const { plaintext: p3 } = ModernCrypto.rsaDecrypt(c3, keys3.privateKey.d, 3233);
    assert(p3 === 65, 'RSA encrypt→decrypt M=65 (p=61,q=53,e=17)', `got ${p3}`);
}

console.log('\n=== MODULAR EXPONENTIATION ===');
{
    const r1 = ModernCrypto.modPow(2, 10, 1000);
    assert(r1.result === 1024 % 1000, '2^10 mod 1000 = 24', `got ${r1.result}`);
    const r2 = ModernCrypto.modPow(3, 5, 13);
    assert(r2.result === (3 ** 5) % 13, '3^5 mod 13 = 9', `got ${r2.result}`);
}

console.log('\n=== EULER TOTIENT ===');
{
    const r1 = ModernCrypto.eulerPhi(12);
    assert(r1.phi === 4, 'φ(12) = 4', `got ${r1.phi}`);
    const r2 = ModernCrypto.eulerPhi(7);
    assert(r2.phi === 6, 'φ(7) = 6 (prime)', `got ${r2.phi}`);
    const r3 = ModernCrypto.eulerPhi(100);
    assert(r3.phi === 40, 'φ(100) = 40', `got ${r3.phi}`);
}

console.log('\n=== EXTENDED GCD ===');
{
    const r1 = ModernCrypto.extendedGCD(120n, 23n);
    assert(r1.gcd === 1n, 'gcd(120,23) = 1', `got ${r1.gcd}`);
    assert(120n * r1.x + 23n * r1.y === 1n, 'Bézout identity holds');

    const r2 = ModernCrypto.extendedGCD(48n, 18n);
    assert(r2.gcd === 6n, 'gcd(48,18) = 6', `got ${r2.gcd}`);
}

console.log('\n=== MODULAR INVERSE ===');
{
    const r1 = ModernCrypto.modInverseBigInt(7, 26);
    assert(r1 === 15n, '7^-1 mod 26 = 15', `got ${r1}`);
    assert((7n * r1) % 26n === 1n, 'Verification: 7*15 mod 26 = 1');

    const r2 = ModernCrypto.modInverseBigInt(3, 11);
    assert(r2 === 4n, '3^-1 mod 11 = 4', `got ${r2}`);
}

console.log('\n' + '='.repeat(50));
console.log(`Results: ${pass} passed, ${fail} failed out of ${pass + fail} tests`);
console.log('='.repeat(50));

if (fail > 0) process.exit(1);
