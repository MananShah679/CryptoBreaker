/**
 * English Text Analyzer Module
 * Advanced statistical analysis for plaintext detection without API
 */

// ==================== ENGLISH DICTIONARIES ====================

// Common English words for dictionary matching
const COMMON_WORDS = [
    // Very common 2-3 letter words
    'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HAD', 'HER', 'WAS', 'ONE', 'OUR', 'OUT',
    'HAS', 'HIS', 'HOW', 'ITS', 'LET', 'MAY', 'NEW', 'NOW', 'OLD', 'SEE', 'WAY', 'WHO', 'BOY', 'DID', 'GET',
    'HIM', 'HIS', 'HOW', 'MAN', 'OWN', 'SAY', 'SHE', 'TWO', 'USE', 'IS', 'IT', 'BE', 'AS', 'AT', 'SO', 'WE',
    'HE', 'BY', 'OR', 'ON', 'DO', 'IF', 'ME', 'MY', 'UP', 'AN', 'GO', 'NO', 'US', 'AM', 'TO', 'OF', 'IN', 'A', 'I',

    // Common 4-5 letter words
    'THAT', 'WITH', 'HAVE', 'THIS', 'WILL', 'YOUR', 'FROM', 'THEY', 'BEEN', 'CALL', 'COME', 'MADE', 'FIND',
    'WERE', 'SAID', 'EACH', 'MAKE', 'LIKE', 'INTO', 'TIME', 'VERY', 'WHEN', 'MORE', 'SOME', 'THAN', 'THEM',
    'WORD', 'WHAT', 'JUST', 'KNOW', 'TAKE', 'WELL', 'BACK', 'GOOD', 'HERE', 'ALSO', 'MUST', 'NAME', 'LONG',
    'OVER', 'SUCH', 'LOOK', 'ONLY', 'YEAR', 'MOST', 'LAST', 'WORK', 'NEED', 'FEEL', 'EVEN', 'WANT', 'GIVE',
    'THESE', 'FIRST', 'COULD', 'WOULD', 'THERE', 'THEIR', 'WHICH', 'ABOUT', 'OTHER', 'AFTER', 'THINK',
    'BEING', 'WHERE', 'EVERY', 'GREAT', 'STILL', 'NEVER', 'THOSE', 'FOUND', 'UNDER', 'WHILE', 'AGAIN',
    'WORLD', 'PLACE', 'SMALL', 'RIGHT', 'LITTLE', 'THREE', 'THING', 'STATE', 'NIGHT', 'HOUSE',

    // Common 6+ letter words
    'PEOPLE', 'SHOULD', 'BEFORE', 'THROUGH', 'DIFFERENT', 'BETWEEN', 'BECAUSE', 'ANOTHER', 'HOWEVER',
    'SOMETHING', 'WITHOUT', 'AGAINST', 'IMPORTANT', 'NOTHING', 'GOVERNMENT', 'TOGETHER', 'CHILDREN',
    'MESSAGE', 'SECRET', 'ATTACK', 'SECURE', 'SYSTEM', 'CIPHER', 'CRYPTOGRAPHY', 'ENCRYPT', 'DECRYPT',
    'HELLO', 'WORLD', 'PASSWORD', 'SECURITY', 'HIDDEN', 'PLAINTEXT', 'CIPHERTEXT', 'INFORMATION'
];

// English letter frequencies (from large corpus analysis)
const ENGLISH_FREQ = {
    'E': 0.127, 'T': 0.091, 'A': 0.082, 'O': 0.075, 'I': 0.070,
    'N': 0.067, 'S': 0.063, 'H': 0.061, 'R': 0.060, 'D': 0.043,
    'L': 0.040, 'C': 0.028, 'U': 0.028, 'M': 0.024, 'W': 0.024,
    'F': 0.022, 'G': 0.020, 'Y': 0.020, 'P': 0.019, 'B': 0.015,
    'V': 0.010, 'K': 0.008, 'J': 0.002, 'X': 0.002, 'Q': 0.001, 'Z': 0.001
};

// Common English bigrams
const COMMON_BIGRAMS = [
    'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND',
    'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR',
    'ST', 'TO', 'NT', 'NG', 'SE', 'HA', 'AS', 'OU', 'IO', 'LE',
    'VE', 'CO', 'ME', 'DE', 'HI', 'RI', 'RO', 'IC', 'NE', 'EA',
    'RA', 'CE', 'LI', 'CH', 'LL', 'BE', 'MA', 'SI', 'OM', 'UR'
];

// Common English trigrams
const COMMON_TRIGRAMS = [
    'THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE', 'FOR', 'ENT',
    'ION', 'TER', 'WAS', 'YOU', 'ITH', 'VER', 'ALL', 'WIT', 'THI', 'TIO',
    'EVE', 'OUR', 'ERS', 'ESS', 'AVE', 'ECT', 'ONE', 'IST', 'RES', 'OTH'
];

// ==================== ANALYSIS FUNCTIONS ====================

function getLetterFrequencies(text) {
    const freq = {};
    const letters = text.replace(/[^A-Z]/g, '');
    const total = letters.length || 1;

    for (const char of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
        freq[char] = 0;
    }

    for (const char of letters) {
        freq[char]++;
    }

    for (const char in freq) {
        freq[char] /= total;
    }

    return freq;
}

function chiSquaredScore(text) {
    const observed = getLetterFrequencies(text);
    let chiSquared = 0;

    for (const char in ENGLISH_FREQ) {
        const expected = ENGLISH_FREQ[char];
        const obs = observed[char] || 0;
        const diff = obs - expected;
        chiSquared += (diff * diff) / expected;
    }

    // Lower chi-squared means closer to English
    // Convert to a 0-1 score where 1 is best
    const normalizedScore = Math.max(0, 1 - (chiSquared / 2));
    return normalizedScore;
}

function bigramScore(text) {
    const cleanedText = text.replace(/[^A-Z]/g, '');
    if (cleanedText.length < 2) return 0;

    let score = 0;
    let total = 0;

    for (let i = 0; i < cleanedText.length - 1; i++) {
        const bigram = cleanedText.substring(i, i + 2);
        if (COMMON_BIGRAMS.includes(bigram)) {
            score++;
        }
        total++;
    }

    return total > 0 ? score / total : 0;
}

function trigramScore(text) {
    const cleanedText = text.replace(/[^A-Z]/g, '');
    if (cleanedText.length < 3) return 0;

    let score = 0;
    let total = 0;

    for (let i = 0; i < cleanedText.length - 2; i++) {
        const trigram = cleanedText.substring(i, i + 3);
        if (COMMON_TRIGRAMS.includes(trigram)) {
            score++;
        }
        total++;
    }

    return total > 0 ? score / total : 0;
}

function dictionaryScore(text) {
    // Split text into words
    const words = text.split(/\s+/).filter(w => w.length > 0);
    if (words.length === 0) {
        // If no spaces, check if entire text or substrings match dictionary
        return singleWordScore(text.replace(/[^A-Z]/g, ''));
    }

    let matchScore = 0;
    let totalWeight = 0;

    for (const word of words) {
        const cleanWord = word.replace(/[^A-Z]/g, '');
        const weight = Math.min(cleanWord.length, 8); // Weight by word length, cap at 8
        totalWeight += weight;

        if (COMMON_WORDS.includes(cleanWord)) {
            matchScore += weight;
        }
    }

    return totalWeight > 0 ? matchScore / totalWeight : 0;
}

function singleWordScore(text) {
    // For texts without spaces, look for embedded common words
    let score = 0;
    let foundWords = [];

    // Try to find common words in the text
    for (const word of COMMON_WORDS) {
        if (word.length >= 3 && text.includes(word)) {
            score += word.length;
            foundWords.push(word);
        }
    }

    // Normalize by text length
    return Math.min(1, score / (text.length || 1));
}

// ==================== COMPOSITE SCORING ====================

const SCORING_WEIGHTS = {
    dictionaryMatch: 0.50,
    letterFrequency: 0.25,
    bigramScore: 0.15,
    trigramScore: 0.10
};

function analyzeText(text) {
    const dictScore = dictionaryScore(text);
    const freqScore = chiSquaredScore(text);
    const biScore = bigramScore(text);
    const triScore = trigramScore(text);

    const compositeScore =
        SCORING_WEIGHTS.dictionaryMatch * dictScore +
        SCORING_WEIGHTS.letterFrequency * freqScore +
        SCORING_WEIGHTS.bigramScore * biScore +
        SCORING_WEIGHTS.trigramScore * triScore;

    return {
        composite: compositeScore,
        dictionary: dictScore,
        frequency: freqScore,
        bigram: biScore,
        trigram: triScore,
        confidence: Math.round(compositeScore * 100)
    };
}

function scoreResults(results) {
    for (const result of results) {
        const analysis = analyzeText(result.plaintext);
        result.score = analysis.composite;
        result.confidence = analysis.confidence;
        result.analysis = analysis;
    }

    // Sort by score descending
    results.sort((a, b) => b.score - a.score);

    return results;
}

// ==================== EXPORTS ====================

export const Analyzer = {
    analyzeText,
    scoreResults,
    COMMON_WORDS,
    ENGLISH_FREQ,
    COMMON_BIGRAMS,
    COMMON_TRIGRAMS
};
