/**
 * Cryptobreaker Background Worker
 * Handles intensive brute-force operations off the main thread
 */

// Import libraries
import { CryptoEngine } from './lib/crypto.js';
import { Analyzer } from './lib/analyzer.js';

// Listen for messages from main thread
self.addEventListener('message', function (e) {
    const data = e.data;

    if (data.type === 'crack') {
        runCrackJob(data);
    }
});

function runCrackJob(data) {
    const { cipher, text, options } = data;
    let results = [];

    try {
        // Report start
        self.postMessage({ type: 'progress', status: 'starting', message: 'Starting analysis...' });

        // Select brute-force method
        switch (cipher) {
            case 'additive':
                results = CryptoEngine.bruteForceAdditive(text);
                break;
            case 'multiplicative':
                results = CryptoEngine.bruteForceMultiplicative(text);
                break;
            case 'affine':
                results = CryptoEngine.bruteForceAffine(text);
                break;
            case 'vigenere':
                results = CryptoEngine.bruteForceVigenere(text);
                break;
            case 'playfair':
                results = CryptoEngine.bruteForcePlayfair(text);
                break;
            case 'hill':
                results = CryptoEngine.bruteForceHill(text);
                break;
            case 'railfence':
                results = CryptoEngine.bruteForceRailFence(text);
                break;
            case 'columnar':
                results = CryptoEngine.bruteForceColumnar(text);
                break;
            case 'double':
                results = CryptoEngine.bruteForceDoubleTransposition(text);
                break;
            case 'product':
                self.postMessage({ type: 'progress', status: 'working', message: 'Crunching product cipher combinations...' });
                const subType = options?.subType || 'vigenere';
                const transType = options?.transType || 'columnar';
                results = CryptoEngine.bruteForceProductCipher(text, subType, transType);
                break;
            case 'autokey':
                results = CryptoEngine.bruteForceAutokey(text);
                break;
            case 'simple-trans':
                results = CryptoEngine.bruteForceSimpleTransposition(text);
                break;
            case 'monoalphabetic':
                // Monoalphabetic has 26! possible keys — not brute-forceable
                // Return a message result
                results = [{
                    key: 'N/A',
                    keyDisplay: 'Dictionary Attack Not Available',
                    plaintext: 'Monoalphabetic cipher has 26! (≈4×10²⁶) possible keys. Use frequency analysis instead.',
                    score: 0
                }];
                break;
            case 'vernam':
                // Vernam / One-Time Pad is theoretically unbreakable
                results = [{
                    key: 'N/A',
                    keyDisplay: 'Unbreakable (One-Time Pad)',
                    plaintext: 'Vernam cipher (OTP) is theoretically unbreakable — every plaintext is equally likely without the key.',
                    score: 0
                }];
                break;
            case 'rsa':
            case 'des':
            case 'aes':
            case 'euler-phi':
            case 'ext-gcd':
            case 'mod-inverse':
            case 'mod-exp':
                results = [{
                    key: 'N/A',
                    keyDisplay: 'Not applicable',
                    plaintext: 'Brute-force is not applicable for this tool. Use the Encrypt operation instead.',
                    score: 0
                }];
                break;
            default:
                throw new Error(`Unknown cipher: ${cipher}`);
        }

        self.postMessage({ type: 'progress', status: 'analyzing', message: 'Scoring candidates...' });

        // Score results
        const scored = Analyzer.scoreResults(results);

        // Send back top results (limit to top 50 to save memory transfer)
        self.postMessage({
            type: 'complete',
            results: scored.slice(0, 50)
        });

    } catch (error) {
        self.postMessage({
            type: 'error',
            message: error.message
        });
    }
}
