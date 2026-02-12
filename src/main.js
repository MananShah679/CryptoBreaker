/**
 * Application Controller
 * Handles UI interactions and coordinates cryptanalysis operations
 */

import { CryptoEngine } from './lib/crypto.js';
import { Analyzer } from './lib/analyzer.js';
import { ModernCrypto } from './lib/modern.js';
import './style.css';

// ==================== STATE ====================
const state = {
    category: 'substitution',
    cipherType: 'additive',
    operations: new Set(['crack']), // Multi-select: encrypt, decrypt, crack
    isProcessing: false
};

// ==================== DOM ELEMENTS ====================
const elements = {
    // Category & Cipher selection
    categoryBtns: document.querySelectorAll('.category-btn'),
    cipherBtns: document.querySelectorAll('.cipher-btn'),
    substitutionCiphers: document.getElementById('substitution-ciphers'),
    transpositionCiphers: document.getElementById('transposition-ciphers'),
    productCiphers: document.getElementById('product-ciphers'),
    symmetricCiphers: document.getElementById('symmetric-ciphers'),
    asymmetricCiphers: document.getElementById('asymmetric-ciphers'),
    mathTools: document.getElementById('math-tools'),

    // Product cipher dropdowns
    productSubCipher: document.getElementById('product-sub-cipher'),
    productTransCipher: document.getElementById('product-trans-cipher'),

    // Operation checkboxes
    opEncrypt: document.getElementById('op-encrypt'),
    opDecrypt: document.getElementById('op-decrypt'),
    opCrack: document.getElementById('op-crack'),

    // Inputs
    encryptInputs: document.getElementById('encrypt-inputs'),
    crackInputs: document.getElementById('crack-inputs'),
    plaintextInput: document.getElementById('plaintext-input'),
    ciphertextInput: document.getElementById('ciphertext-input'),
    keyInputs: document.getElementById('key-inputs'),

    // Buttons
    executeBtn: document.getElementById('execute-btn'),
    btnText: document.getElementById('btn-text'),
    clearBtn: document.getElementById('clear-history'),
    exportBtn: document.getElementById('export-history'),
    quickBtns: document.querySelectorAll('.quick-btn'),

    // Output
    encryptionOutput: document.getElementById('encryption-output'),
    cipherResult: document.getElementById('cipher-result'),

    // Results
    resultsSection: document.getElementById('results-section'),
    emptyState: document.getElementById('empty-state'),
    loadingState: document.getElementById('loading-state'),
    topCandidates: document.getElementById('top-candidates'),
    candidatesContainer: document.getElementById('candidates-container'),
    allResultsToggle: document.getElementById('all-results-toggle'),
    toggleAllBtn: document.getElementById('toggle-all-btn'),
    allResults: document.getElementById('all-results'),
    allResultsContainer: document.getElementById('all-results-container'),
    toastContainer: document.getElementById('toast-container')
};

// ==================== TOAST NOTIFICATIONS ====================
function showToast(message, type = 'info') {
    if (!elements.toastContainer) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${type === 'error' ? '!' : type === 'success' ? '✓' : 'i'}</span> ${message}`;

    elements.toastContainer.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });

    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Override alert for better UX
window.alert = (msg) => showToast(msg, 'error');


// ==================== INITIALIZATION ====================
function init() {
    // Category selection
    elements.categoryBtns.forEach(btn => {
        btn.addEventListener('click', () => selectCategory(btn.dataset.category));
    });

    // Cipher type selection
    elements.cipherBtns.forEach(btn => {
        btn.addEventListener('click', () => selectCipher(btn.dataset.cipher));
    });

    // Product cipher dropdown changes
    elements.productSubCipher.addEventListener('change', updateKeyInputs);
    elements.productTransCipher.addEventListener('change', updateKeyInputs);

    // Operation checkbox changes
    elements.opEncrypt.addEventListener('change', updateOperations);
    elements.opDecrypt.addEventListener('change', updateOperations);
    elements.opCrack.addEventListener('change', updateOperations);

    // Quick load buttons
    elements.quickBtns.forEach(btn => {
        btn.addEventListener('click', () => quickLoad(btn.dataset.cipher, btn.dataset.text));
    });

    // Execute button
    elements.executeBtn?.addEventListener('click', execute);

    // Clear button
    elements.clearBtn?.addEventListener('click', clearAll);

    // Toggle all results
    elements.toggleAllBtn?.addEventListener('click', toggleAllResults);

    // Theme toggle
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
    }

    // Load saved theme
    loadSavedTheme();

    // Initialize
    updateKeyInputs();
    updateOperations();
    initDragAndDrop();
    initHistory();
}

// ==================== HISTORY MANAGEMENT ====================
let historyLog = [];

function initHistory() {
    const panel = document.getElementById('history-panel');
    const toggleBtn = document.getElementById('history-toggle');
    const closeBtn = document.getElementById('close-history');
    const clearBtn = document.getElementById('clear-history');
    const exportBtn = document.getElementById('export-history');

    if (!panel) return;

    toggleBtn.addEventListener('click', () => panel.classList.add('active'));
    closeBtn.addEventListener('click', () => panel.classList.remove('active'));

    clearBtn.addEventListener('click', () => {
        historyLog = [];
        renderHistory();
    });

    if (exportBtn) {
        exportBtn.addEventListener('click', exportHistory);
    }
}

function exportHistory() {
    if (historyLog.length === 0) return;

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(historyLog, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "cryptobreaker_session_" + new Date().toISOString().slice(0, 10) + ".json");
    document.body.appendChild(downloadAnchorNode); // required for firefox
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

function addToHistory(type, input, result, details = {}) {
    const entry = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        type,
        cipherType: state.cipherType,
        input: input.substring(0, 50) + (input.length > 50 ? '...' : ''),
        fullInput: input,
        result: result ? (typeof result === 'string' ? result.substring(0, 50) + '...' : 'Analysis Results') : '',
        fullResult: result,
        details // logs keys used etc
    };

    historyLog.unshift(entry);
    if (historyLog.length > 20) historyLog.pop(); // Keep last 20
    renderHistory();
}

function renderHistory() {
    const container = document.getElementById('history-list');
    if (!container) return;

    if (historyLog.length === 0) {
        container.innerHTML = '<div class="history-empty">No operations yet</div>';
        return;
    }

    container.innerHTML = historyLog.map(entry => `
        <div class="history-item" onclick="restoreHistory(${entry.id})">
            <div class="history-item-header">
                <span>${entry.timestamp}</span>
                <span>${entry.cipherType}</span>
            </div>
            <div class="history-item-title">${entry.type}</div>
            <div class="history-item-preview">In: ${entry.input}</div>
            <div class="history-item-preview">Out: ${entry.result}</div>
        </div>
    `).join('');
}

function restoreHistory(id) {
    const entry = historyLog.find(e => e.id === id);
    if (!entry) return;

    // Restore State
    selectCategory(getCategoryForCipher(entry.cipherType));
    selectCipher(entry.cipherType);

    // Restore Inputs
    if (entry.type === 'ENCRYPT') {
        elements.plaintextInput.value = entry.fullInput;
        elements.opEncrypt.click();
    } else {
        elements.ciphertextInput.value = entry.fullInput;
        // If it was a crack, show results
        if (entry.type === 'CRACK') {
            displayResults(entry.fullResult);
        } else {
            elements.opDecrypt.click();
        }
    }

    // Close panel
    document.getElementById('history-panel').classList.remove('active');
}

function getCategoryForCipher(cipher) {
    if (['additive', 'multiplicative', 'affine', 'vigenere', 'playfair', 'hill'].includes(cipher)) return 'substitution';
    if (['railfence', 'columnar', 'double'].includes(cipher)) return 'transposition';
    return 'product';
}

// ==================== DRAG & DROP ====================
function initDragAndDrop() {
    setupDropZone('plaintext-drop-zone', 'plaintext-input');
    setupDropZone('ciphertext-drop-zone', 'ciphertext-input');
}

function setupDropZone(zoneId, inputId) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    if (!zone || !input) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        zone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        zone.addEventListener(eventName, () => zone.classList.add('drag-over'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        zone.addEventListener(eventName, () => zone.classList.remove('drag-over'), false);
    });

    zone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files, input);
    }, false);
}

function handleFiles(files, inputElement) {
    if (files.length === 0) return;
    const file = files[0];

    if (file.type && !file.type.startsWith('text/')) {
        alert('Please drop a text file');
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        inputElement.value = e.target.result;
    };
    reader.readAsText(file);
}

// ==================== CATEGORY SELECTION ====================
function selectCategory(category) {
    state.category = category;

    elements.categoryBtns.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.category === category);
    });

    // Show/hide cipher groups
    elements.substitutionCiphers.classList.toggle('hidden', category !== 'substitution');
    elements.transpositionCiphers.classList.toggle('hidden', category !== 'transposition');
    elements.productCiphers.classList.toggle('hidden', category !== 'product');
    if (elements.symmetricCiphers) elements.symmetricCiphers.classList.toggle('hidden', category !== 'symmetric');
    if (elements.asymmetricCiphers) elements.asymmetricCiphers.classList.toggle('hidden', category !== 'asymmetric');
    if (elements.mathTools) elements.mathTools.classList.toggle('hidden', category !== 'math');

    // Select first cipher in category
    let firstCipher;
    if (category === 'substitution') firstCipher = 'additive';
    else if (category === 'transposition') firstCipher = 'simple-trans';
    else if (category === 'symmetric') firstCipher = 'des';
    else if (category === 'asymmetric') firstCipher = 'rsa';
    else if (category === 'math') firstCipher = 'euler-phi';
    else firstCipher = 'product';

    selectCipher(firstCipher);
}

// ==================== CIPHER SELECTION ====================
function selectCipher(cipher) {
    state.cipherType = cipher;

    elements.cipherBtns.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.cipher === cipher);
    });

    updateKeyInputs();
}

// ==================== OPERATION SELECTION (MULTI-SELECT) ====================
function updateOperations() {
    state.operations.clear();

    if (elements.opEncrypt.checked) state.operations.add('encrypt');
    if (elements.opDecrypt.checked) state.operations.add('decrypt');
    if (elements.opCrack.checked) state.operations.add('crack');

    // Update UI based on selected operations
    const needsPlaintext = state.operations.has('encrypt');
    const needsCiphertext = state.operations.has('decrypt') || state.operations.has('crack');
    const needsKey = state.operations.has('encrypt') || state.operations.has('decrypt');

    elements.encryptInputs.classList.toggle('hidden', !needsPlaintext && !needsKey);
    elements.crackInputs.classList.toggle('hidden', !needsCiphertext);

    // Always show key inputs if any operation needs them
    if (needsKey) {
        elements.encryptInputs.classList.remove('hidden');
    }

    // Update button text
    const ops = [];
    if (state.operations.has('encrypt')) ops.push('ENCRYPT');
    if (state.operations.has('decrypt')) ops.push('DECRYPT');
    if (state.operations.has('crack')) ops.push('CRACK');
    elements.btnText.textContent = ops.length > 0 ? ops.join(' + ') : 'SELECT OPERATION';
}

function updateKeyInputs() {
    let html = '';

    switch (state.cipherType) {
        case 'additive':
            html = '<input type="number" id="key-k" placeholder="Key k (0-25)" min="0" max="25">';
            break;
        case 'multiplicative':
            html = '<input type="number" id="key-k" placeholder="Key k (coprime with 26)" min="1" max="25">';
            break;
        case 'affine':
            html = `
                <input type="number" id="key-a" placeholder="a (coprime with 26)" min="1" max="25">
                <input type="number" id="key-b" placeholder="b (0-25)" min="0" max="25">
            `;
            break;
        case 'monoalphabetic':
            html = '<input type="text" id="key-word" placeholder="Keyword to generate alphabet (e.g., SECRET)">';
            break;
        case 'vigenere':
            html = '<input type="text" id="key-word" placeholder="Keyword (e.g., LEMON)">';
            break;
        case 'autokey':
            html = '<input type="number" id="key-k" placeholder="Initial key (0-25)" min="0" max="25">';
            break;
        case 'playfair':
            html = '<input type="text" id="key-word" placeholder="Keyword (e.g., MONARCHY)">';
            break;
        case 'hill':
            html = `
                <input type="number" id="key-a" placeholder="a" min="0" max="25">
                <input type="number" id="key-b" placeholder="b" min="0" max="25">
                <input type="number" id="key-c" placeholder="c" min="0" max="25">
                <input type="number" id="key-d" placeholder="d" min="0" max="25">
            `;
            break;
        case 'vernam':
            html = '<input type="text" id="key-word" placeholder="Key (must be same length as plaintext)">';
            break;
        case 'simple-trans':
            html = '<input type="number" id="key-cols" placeholder="Number of columns (2-10)" min="2" max="10">';
            break;
        case 'railfence':
            html = '<input type="number" id="key-rails" placeholder="Number of rails (2-10)" min="2" max="20">';
            break;
        case 'columnar':
            html = '<input type="text" id="key-word" placeholder="Keyword (e.g., ZEBRA)">';
            break;
        case 'double':
            html = `
                <input type="text" id="key-word1" placeholder="First keyword">
                <input type="text" id="key-word2" placeholder="Second keyword">
            `;
            break;
        case 'des':
        case 'aes':
            html = `
                <input type="text" id="key-block" placeholder="8-char key (DES) or 16-char (AES)">
                <p class="key-hint">Educational demo - shows algorithm structure</p>
            `;
            break;
        case 'rsa':
            html = `
                <div class="rsa-inputs">
                    <input type="number" id="key-p" placeholder="Prime p (e.g., 7)">
                    <input type="number" id="key-q" placeholder="Prime q (e.g., 17)">
                    <input type="number" id="key-e" placeholder="Public exponent e (optional)">
                    <input type="number" id="key-m" placeholder="Message M (number)">
                </div>
            `;
            break;
        case 'euler-phi':
            html = '<input type="number" id="key-n" placeholder="Number n to calculate φ(n)">';
            break;
        case 'ext-gcd':
            html = `
                <input type="number" id="key-a" placeholder="Number a">
                <input type="number" id="key-b" placeholder="Number b">
            `;
            break;
        case 'mod-inverse':
            html = `
                <input type="number" id="key-a" placeholder="Number a">
                <input type="number" id="key-m" placeholder="Modulus m">
            `;
            break;
        case 'mod-exp':
            html = `
                <input type="number" id="key-base" placeholder="Base">
                <input type="number" id="key-exp" placeholder="Exponent">
                <input type="number" id="key-mod" placeholder="Modulus">
            `;
            break;
        case 'product': {
            // Generate key inputs based on selected sub and trans ciphers
            const subCipher = elements.productSubCipher.value;
            const transCipher = elements.productTransCipher.value;

            // Substitution cipher key input
            html = '<div class="product-key-section"><strong>Substitution Key:</strong>';
            switch (subCipher) {
                case 'additive':
                    html += '<input type="number" id="key-sub-k" placeholder="k (0-25)" min="0" max="25">';
                    break;
                case 'multiplicative':
                    html += '<input type="number" id="key-sub-k" placeholder="k (coprime)" min="1" max="25">';
                    break;
                case 'affine':
                    html += `<input type="number" id="key-sub-a" placeholder="a" min="1" max="25">
                             <input type="number" id="key-sub-b" placeholder="b" min="0" max="25">`;
                    break;
                case 'vigenere':
                case 'playfair':
                    html += '<input type="text" id="key-sub-word" placeholder="Keyword">';
                    break;
                case 'hill':
                    html += `<input type="number" id="key-sub-a" placeholder="a">
                             <input type="number" id="key-sub-b" placeholder="b">
                             <input type="number" id="key-sub-c" placeholder="c">
                             <input type="number" id="key-sub-d" placeholder="d">`;
                    break;
            }
            html += '</div>';

            // Transposition cipher key input
            html += '<div class="product-key-section"><strong>Transposition Key:</strong>';
            switch (transCipher) {
                case 'railfence':
                    html += '<input type="number" id="key-trans-rails" placeholder="Rails (2-20)" min="2" max="20">';
                    break;
                case 'columnar':
                    html += '<input type="text" id="key-trans-word" placeholder="Keyword">';
                    break;
                case 'double':
                    html += `<input type="text" id="key-trans-word1" placeholder="First keyword">
                             <input type="text" id="key-trans-word2" placeholder="Second keyword">`;
                    break;
            }
            html += '</div>';
            break;
        }
    }

    elements.keyInputs.innerHTML = html;
}

// ==================== QUICK LOAD ====================
function quickLoad(cipher, text) {
    // Determine category from cipher
    const substitutionCiphers = ['additive', 'multiplicative', 'affine', 'vigenere', 'playfair', 'hill'];
    const transpositionCiphers = ['railfence', 'columnar', 'double'];
    let category;
    if (substitutionCiphers.includes(cipher)) category = 'substitution';
    else if (transpositionCiphers.includes(cipher)) category = 'transposition';
    else category = 'product';

    selectCategory(category);
    selectCipher(cipher);
    // Enable only crack for quick load
    elements.opCrack.checked = true;
    elements.opEncrypt.checked = false;
    elements.opDecrypt.checked = false;
    updateOperations();
    elements.ciphertextInput.value = text;
}

// ==================== EXECUTION ====================
async function execute() {
    if (state.isProcessing) return;
    if (state.operations.size === 0) {
        alert('Please select at least one operation');
        return;
    }

    state.isProcessing = true;
    showLoading();
    elements.emptyState.classList.add('hidden');

    // Small delay for UI feedback
    await new Promise(resolve => setTimeout(resolve, 100));

    try {
        let encryptedCiphertext = null;

        // Run operations in order: Encrypt -> Decrypt -> Crack
        if (state.operations.has('encrypt')) {
            encryptedCiphertext = executeEncrypt();
            if (!encryptedCiphertext) {
                state.isProcessing = false;
                return;
            }
        }

        if (state.operations.has('decrypt')) {
            // If we just encrypted, use that as ciphertext for decrypt
            if (encryptedCiphertext) {
                elements.ciphertextInput.value = encryptedCiphertext;
            }
            const decryptedPlaintext = executeDecrypt();
            if (!decryptedPlaintext && state.operations.size === 1) {
                state.isProcessing = false;
                return;
            }
        }

        if (state.operations.has('crack')) {
            // If we encrypted and haven't decrypted, use encrypted text
            if (encryptedCiphertext && !state.operations.has('decrypt')) {
                elements.ciphertextInput.value = encryptedCiphertext;
            }
            await executeCrack();
        } else {
            hideLoading();
        }
    } catch (error) {
        console.error('Execution error:', error);
        alert('Error: ' + error.message);
        hideLoading();
    }

    state.isProcessing = false;
}

function executeEncrypt() {
    const modernCiphers = ['rsa', 'des', 'aes', 'euler-phi', 'ext-gcd', 'mod-inverse', 'mod-exp'];
    const plaintext = CryptoEngine.cleanText(elements.plaintextInput.value);

    if (!plaintext && !modernCiphers.includes(state.cipherType)) {
        hideLoading();
        alert('Please enter plaintext to encrypt');
        return;
    }

    let ciphertext;

    switch (state.cipherType) {
        case 'additive': {
            const k = parseInt(document.getElementById('key-k').value);
            if (isNaN(k) || k < 0 || k > 25) {
                hideLoading();
                alert('Key must be between 0 and 25');
                return;
            }
            ciphertext = CryptoEngine.encryptAdditive(plaintext, k);
            break;
        }
        case 'multiplicative': {
            const k = parseInt(document.getElementById('key-k').value);
            if (isNaN(k) || !CryptoEngine.getValidMultiplicativeKeys().includes(k)) {
                hideLoading();
                alert('Key must be coprime with 26 (valid: 1,3,5,7,9,11,15,17,19,21,23,25)');
                return;
            }
            ciphertext = CryptoEngine.encryptMultiplicative(plaintext, k);
            break;
        }
        case 'affine': {
            const a = parseInt(document.getElementById('key-a').value);
            const b = parseInt(document.getElementById('key-b').value);
            if (isNaN(a) || !CryptoEngine.getValidMultiplicativeKeys().includes(a)) {
                hideLoading();
                alert('a must be coprime with 26');
                return;
            }
            if (isNaN(b) || b < 0 || b > 25) {
                hideLoading();
                alert('b must be between 0 and 25');
                return;
            }
            ciphertext = CryptoEngine.encryptAffine(plaintext, a, b);
            break;
        }
        case 'vigenere': {
            const key = document.getElementById('key-word').value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a keyword');
                return;
            }
            ciphertext = CryptoEngine.encryptVigenere(plaintext, key);
            break;
        }
        case 'playfair': {
            const key = document.getElementById('key-word').value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a keyword');
                return;
            }
            ciphertext = CryptoEngine.encryptPlayfair(plaintext, key);
            break;
        }
        case 'hill': {
            const a = parseInt(document.getElementById('key-a').value);
            const b = parseInt(document.getElementById('key-b').value);
            const c = parseInt(document.getElementById('key-c').value);
            const d = parseInt(document.getElementById('key-d').value);
            if ([a, b, c, d].some(isNaN)) {
                hideLoading();
                alert('Please enter all matrix values (a,b,c,d)');
                return;
            }
            ciphertext = CryptoEngine.encryptHill(plaintext, [[a, b], [c, d]]);
            break;
        }
        case 'railfence': {
            const rails = parseInt(document.getElementById('key-rails').value);
            if (isNaN(rails) || rails < 2) {
                hideLoading();
                alert('Rails must be at least 2');
                return;
            }
            ciphertext = CryptoEngine.encryptRailFence(plaintext, rails);
            break;
        }
        case 'columnar': {
            const key = document.getElementById('key-word').value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a keyword');
                return;
            }
            ciphertext = CryptoEngine.encryptColumnar(plaintext, key);
            break;
        }
        case 'double': {
            const key1 = document.getElementById('key-word1').value.toUpperCase();
            const key2 = document.getElementById('key-word2').value.toUpperCase();
            if (!key1 || !key2) {
                hideLoading();
                alert('Please enter both keywords');
                return;
            }
            ciphertext = CryptoEngine.encryptDoubleTransposition(plaintext, key1, key2);
            break;
        }
        case 'product': {
            // Get selected cipher types
            const subCipherType = elements.productSubCipher.value;
            const transCipherType = elements.productTransCipher.value;

            // Build substitution key based on selected cipher
            let subKey = {};
            try {
                switch (subCipherType) {
                    case 'additive':
                    case 'multiplicative':
                        subKey = { k: parseInt(document.getElementById('key-sub-k').value) };
                        if (isNaN(subKey.k)) throw new Error('Invalid key');
                        break;
                    case 'affine':
                        subKey = {
                            a: parseInt(document.getElementById('key-sub-a').value),
                            b: parseInt(document.getElementById('key-sub-b').value)
                        };
                        if (isNaN(subKey.a) || isNaN(subKey.b)) throw new Error('Invalid key');
                        break;
                    case 'vigenere':
                    case 'playfair':
                        subKey = { word: document.getElementById('key-sub-word').value.toUpperCase() };
                        if (!subKey.word) throw new Error('Invalid key');
                        break;
                    case 'hill':
                        subKey = {
                            matrix: [
                                [parseInt(document.getElementById('key-sub-a').value), parseInt(document.getElementById('key-sub-b').value)],
                                [parseInt(document.getElementById('key-sub-c').value), parseInt(document.getElementById('key-sub-d').value)]
                            ]
                        };
                        break;
                }
            } catch (e) {
                hideLoading();
                alert('Please enter valid substitution key');
                return;
            }

            // Build transposition key based on selected cipher
            let transKey = {};
            try {
                switch (transCipherType) {
                    case 'railfence':
                        transKey = { rails: parseInt(document.getElementById('key-trans-rails').value) };
                        if (isNaN(transKey.rails) || transKey.rails < 2) throw new Error('Invalid rails');
                        break;
                    case 'columnar':
                        transKey = { word: document.getElementById('key-trans-word').value.toUpperCase() };
                        if (!transKey.word) throw new Error('Invalid key');
                        break;
                    case 'double':
                        transKey = {
                            word1: document.getElementById('key-trans-word1').value.toUpperCase(),
                            word2: document.getElementById('key-trans-word2').value.toUpperCase()
                        };
                        if (!transKey.word1 || !transKey.word2) throw new Error('Invalid keys');
                        break;
                }
            } catch (e) {
                hideLoading();
                alert('Please enter valid transposition key');
                return;
            }

            const result = CryptoEngine.encryptProductCipherFlexible(plaintext, subCipherType, subKey, transCipherType, transKey);

            // Get cipher names for display
            const subName = subCipherType.charAt(0).toUpperCase() + subCipherType.slice(1);
            const transName = transCipherType.charAt(0).toUpperCase() + transCipherType.slice(1);

            elements.cipherResult.innerHTML = `
                <div style="margin-bottom: 0.5rem;">After ${subName}: ${result.afterSubstitution}</div>
                <div>Final Product: ${result.finalCipher}</div>
            `;
            elements.encryptionOutput.querySelector('h3').textContent = `Encrypted (${subName} + ${transName})`;
            elements.encryptionOutput.classList.remove('hidden');
            elements.emptyState.classList.add('hidden');
            return result.finalCipher;
        }
        case 'autokey': {
            const k = parseInt(document.getElementById('key-k').value);
            if (isNaN(k) || k < 0 || k > 25) {
                hideLoading();
                alert('Initial key must be between 0 and 25');
                return;
            }
            const result = CryptoEngine.encryptAutokey(plaintext, k);
            ciphertext = result.ciphertext;
            break;
        }
        case 'monoalphabetic': {
            const keyword = document.getElementById('key-word').value.toUpperCase();
            if (!keyword) {
                hideLoading();
                alert('Please enter a keyword');
                return;
            }
            const keyAlphabet = CryptoEngine.generateMonoalphabeticKey(keyword);
            ciphertext = CryptoEngine.encryptMonoalphabetic(plaintext, keyAlphabet);
            break;
        }
        case 'vernam': {
            const key = document.getElementById('key-word').value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a key');
                return;
            }
            try {
                const result = CryptoEngine.encryptVernam(plaintext, key);
                ciphertext = result.ciphertext;
            } catch (e) {
                hideLoading();
                alert(e.message);
                return;
            }
            break;
        }
        case 'simple-trans': {
            const cols = parseInt(document.getElementById('key-cols').value);
            if (isNaN(cols) || cols < 2 || cols > 10) {
                hideLoading();
                alert('Number of columns must be between 2 and 10');
                return;
            }
            ciphertext = CryptoEngine.encryptSimpleTransposition(plaintext, cols);
            break;
        }
        case 'rsa': {
            const p = parseInt(document.getElementById('key-p')?.value);
            const q = parseInt(document.getElementById('key-q')?.value);
            const eVal = parseInt(document.getElementById('key-e')?.value) || null;
            const m = parseInt(document.getElementById('key-m')?.value);
            if (isNaN(p) || isNaN(q)) {
                hideLoading();
                alert('Please enter prime numbers p and q');
                return;
            }
            if (isNaN(m)) {
                hideLoading();
                alert('Please enter a message number M');
                return;
            }
            try {
                const keys = ModernCrypto.rsaGenerateKeys(p, q, eVal);
                const encrypted = ModernCrypto.rsaEncrypt(m, keys.publicKey.e, keys.publicKey.n);
                const decrypted = ModernCrypto.rsaDecrypt(encrypted.ciphertext, keys.privateKey.d, keys.privateKey.n);

                let stepsHtml = '<div class="modern-steps">';
                stepsHtml += '<h4>Key Generation</h4>';
                keys.steps.forEach(s => {
                    stepsHtml += `<div class="step-line"><strong>Step ${s.step}:</strong> ${s.description}<br><code>${s.formula || ''}</code> = <strong>${s.result}</strong></div>`;
                });
                stepsHtml += `<h4>Public Key: (e=${keys.publicKey.e}, n=${keys.publicKey.n})</h4>`;
                stepsHtml += `<h4>Private Key: (d=${keys.privateKey.d}, n=${keys.privateKey.n})</h4>`;
                stepsHtml += '<h4>Encryption</h4>';
                stepsHtml += `<div class="step-line">C = M<sup>e</sup> mod n = ${m}<sup>${keys.publicKey.e}</sup> mod ${keys.publicKey.n} = <strong>${encrypted.ciphertext}</strong></div>`;
                stepsHtml += '<h4>Decryption (Verification)</h4>';
                stepsHtml += `<div class="step-line">M = C<sup>d</sup> mod n = ${encrypted.ciphertext}<sup>${keys.privateKey.d}</sup> mod ${keys.privateKey.n} = <strong>${decrypted.plaintext}</strong></div>`;
                stepsHtml += `<div class="step-line">✓ Original M = ${m}, Decrypted M = ${decrypted.plaintext}</div>`;
                stepsHtml += '</div>';

                elements.cipherResult.innerHTML = stepsHtml;
                elements.encryptionOutput.querySelector('h3').textContent = 'RSA Results';
                elements.encryptionOutput.classList.remove('hidden');
                elements.emptyState.classList.add('hidden');
                hideLoading();
                addToHistory('RSA', `M=${m}, p=${p}, q=${q}`, `C=${encrypted.ciphertext}`);
                return String(encrypted.ciphertext);
            } catch (e) {
                hideLoading();
                alert('RSA Error: ' + e.message);
                return;
            }
        }
        case 'des': {
            const key = document.getElementById('key-block')?.value || 'SECRETKE';
            const result = ModernCrypto.desDemo(plaintext.substring(0, 8) || 'HELLOWOR', key);
            let html = '<div class="modern-steps">';
            result.steps.forEach(s => {
                html += `<div class="step-line"><strong>${s.step}:</strong> ${s.description || ''}`;
                if (s.operations) html += '<ul>' + s.operations.map(op => `<li>${typeof op === 'string' ? op : op.name + ': ' + op.description}</li>`).join('') + '</ul>';
                html += '</div>';
            });
            html += `<div class="step-line"><em>Block Size: ${result.blockSize}, Key Size: ${result.keySize}, Rounds: ${result.rounds}</em></div>`;
            html += '</div>';
            elements.cipherResult.innerHTML = html;
            elements.encryptionOutput.querySelector('h3').textContent = 'DES Educational Demo';
            elements.encryptionOutput.classList.remove('hidden');
            elements.emptyState.classList.add('hidden');
            hideLoading();
            return 'DES_DEMO';
        }
        case 'aes': {
            const key = document.getElementById('key-block')?.value || 'SECRETKEYSECRETK';
            const result = ModernCrypto.aesDemo(plaintext.substring(0, 16) || 'HELLOWORLDHELLOW', key);
            let html = '<div class="modern-steps">';
            result.steps.forEach(s => {
                html += `<div class="step-line"><strong>${s.step}:</strong> ${s.description || ''}`;
                if (s.operations) html += '<ul>' + s.operations.map(op => `<li>${typeof op === 'string' ? op : op.name + ': ' + op.description}</li>`).join('') + '</ul>';
                if (s.note) html += `<em>(${s.note})</em>`;
                html += '</div>';
            });
            html += `<div class="step-line"><em>Block Size: ${result.blockSize}, Key Size: ${result.keySize}, Rounds: ${result.rounds}</em></div>`;
            html += '</div>';
            elements.cipherResult.innerHTML = html;
            elements.encryptionOutput.querySelector('h3').textContent = 'AES Educational Demo';
            elements.encryptionOutput.classList.remove('hidden');
            elements.emptyState.classList.add('hidden');
            hideLoading();
            return 'AES_DEMO';
        }
        case 'euler-phi': {
            const n = parseInt(document.getElementById('key-n')?.value);
            if (isNaN(n) || n < 2) {
                hideLoading();
                alert('Please enter a number n ≥ 2');
                return;
            }
            const result = ModernCrypto.eulerPhi(n);
            let html = '<div class="modern-steps">';
            html += `<h4>φ(${n}) = ${result.phi}</h4>`;
            result.steps.forEach(s => {
                html += `<div class="step-line"><strong>${s.step}:</strong> ${JSON.stringify(s.factors || s.result)}</div>`;
            });
            html += '</div>';
            elements.cipherResult.innerHTML = html;
            elements.encryptionOutput.querySelector('h3').textContent = `Euler's Totient φ(${n})`;
            elements.encryptionOutput.classList.remove('hidden');
            elements.emptyState.classList.add('hidden');
            hideLoading();
            return String(result.phi);
        }
        case 'ext-gcd': {
            const a = parseInt(document.getElementById('key-a')?.value);
            const b = parseInt(document.getElementById('key-b')?.value);
            if (isNaN(a) || isNaN(b)) {
                hideLoading();
                alert('Please enter numbers a and b');
                return;
            }
            try {
                const result = ModernCrypto.extendedGCD(BigInt(a), BigInt(b));
                let html = '<div class="modern-steps">';
                html += `<h4>gcd(${a}, ${b}) = ${result.gcd.toString()}</h4>`;
                html += `<div class="step-line">Bézout coefficients: x = ${result.x.toString()}, y = ${result.y.toString()}</div>`;
                html += `<div class="step-line">Verification: ${a} × ${result.x.toString()} + ${b} × ${result.y.toString()} = ${(BigInt(a) * result.x + BigInt(b) * result.y).toString()}</div>`;
                html += '</div>';
                elements.cipherResult.innerHTML = html;
                elements.encryptionOutput.querySelector('h3').textContent = 'Extended GCD Result';
                elements.encryptionOutput.classList.remove('hidden');
                elements.emptyState.classList.add('hidden');
                hideLoading();
                return result.gcd.toString();
            } catch (e) {
                hideLoading();
                alert('Error: ' + e.message);
                return;
            }
        }
        case 'mod-inverse': {
            const a = parseInt(document.getElementById('key-a')?.value);
            const m = parseInt(document.getElementById('key-m')?.value);
            if (isNaN(a) || isNaN(m)) {
                hideLoading();
                alert('Please enter numbers a and m');
                return;
            }
            try {
                const result = ModernCrypto.modInverseBigInt(a, m);
                let html = '<div class="modern-steps">';
                html += `<h4>${a}<sup>-1</sup> mod ${m} = ${result.toString()}</h4>`;
                html += `<div class="step-line">Verification: ${a} × ${result.toString()} mod ${m} = ${(BigInt(a) * result % BigInt(m)).toString()}</div>`;
                html += '</div>';
                elements.cipherResult.innerHTML = html;
                elements.encryptionOutput.querySelector('h3').textContent = 'Modular Inverse Result';
                elements.encryptionOutput.classList.remove('hidden');
                elements.emptyState.classList.add('hidden');
                hideLoading();
                return result.toString();
            } catch (e) {
                hideLoading();
                alert('Error: ' + e.message);
                return;
            }
        }
        case 'mod-exp': {
            const base = parseInt(document.getElementById('key-base')?.value);
            const exp = parseInt(document.getElementById('key-exp')?.value);
            const mod = parseInt(document.getElementById('key-mod')?.value);
            if (isNaN(base) || isNaN(exp) || isNaN(mod)) {
                hideLoading();
                alert('Please enter base, exponent, and modulus');
                return;
            }
            const result = ModernCrypto.modPow(base, exp, mod);
            let html = '<div class="modern-steps">';
            html += `<h4>${base}<sup>${exp}</sup> mod ${mod} = ${result.result}</h4>`;
            if (result.steps.length > 0) {
                html += '<h4>Steps (Square & Multiply)</h4>';
                result.steps.forEach(s => {
                    html += `<div class="step-line">exp=${s.exp}, result=${s.result}</div>`;
                });
            }
            html += '</div>';
            elements.cipherResult.innerHTML = html;
            elements.encryptionOutput.querySelector('h3').textContent = 'Modular Exponentiation Result';
            elements.encryptionOutput.classList.remove('hidden');
            elements.emptyState.classList.add('hidden');
            hideLoading();
            return String(result.result);
        }
    }

    // Show encryption result
    const outputHeader = elements.encryptionOutput.querySelector('h3');
    if (outputHeader) outputHeader.textContent = 'Encrypted Ciphertext';
    elements.cipherResult.textContent = ciphertext;
    elements.encryptionOutput.classList.remove('hidden');
    elements.emptyState.classList.add('hidden');

    addToHistory('ENCRYPT', plaintext, ciphertext);
    return ciphertext; // Return for chaining
}

function executeDecrypt() {
    const ciphertext = CryptoEngine.cleanText(elements.ciphertextInput.value);

    if (!ciphertext) {
        hideLoading();
        alert('Please enter ciphertext to decrypt');
        return;
    }

    // Need key for decryption - show key inputs
    elements.encryptInputs.classList.remove('hidden');

    let plaintext;

    switch (state.cipherType) {
        case 'additive': {
            const k = parseInt(document.getElementById('key-k')?.value);
            if (isNaN(k) || k < 0 || k > 25) {
                hideLoading();
                alert('Please enter a valid key (0-25) in the Encryption Key field');
                return;
            }
            plaintext = CryptoEngine.decryptAdditive(ciphertext, k);
            break;
        }
        case 'multiplicative': {
            const k = parseInt(document.getElementById('key-k')?.value);
            if (isNaN(k) || !CryptoEngine.getValidMultiplicativeKeys().includes(k)) {
                hideLoading();
                alert('Please enter a valid key (coprime with 26)');
                return;
            }
            plaintext = CryptoEngine.decryptMultiplicative(ciphertext, k);
            break;
        }
        case 'affine': {
            const a = parseInt(document.getElementById('key-a')?.value);
            const b = parseInt(document.getElementById('key-b')?.value);
            if (isNaN(a) || !CryptoEngine.getValidMultiplicativeKeys().includes(a)) {
                hideLoading();
                alert('Please enter valid key a (coprime with 26)');
                return;
            }
            if (isNaN(b) || b < 0 || b > 25) {
                hideLoading();
                alert('Please enter valid key b (0-25)');
                return;
            }
            plaintext = CryptoEngine.decryptAffine(ciphertext, a, b);
            break;
        }
        case 'vigenere': {
            const key = document.getElementById('key-word')?.value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a keyword');
                return;
            }
            plaintext = CryptoEngine.decryptVigenere(ciphertext, key);
            break;
        }
        case 'playfair': {
            const key = document.getElementById('key-word')?.value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a keyword');
                return;
            }
            plaintext = CryptoEngine.decryptPlayfair(ciphertext, key);
            break;
        }
        case 'hill': {
            const a = parseInt(document.getElementById('key-a')?.value);
            const b = parseInt(document.getElementById('key-b')?.value);
            const c = parseInt(document.getElementById('key-c')?.value);
            const d = parseInt(document.getElementById('key-d')?.value);
            if ([a, b, c, d].some(isNaN)) {
                hideLoading();
                alert('Please enter all matrix values (a,b,c,d)');
                return;
            }
            plaintext = CryptoEngine.decryptHill(ciphertext, [[a, b], [c, d]]);
            break;
        }
        case 'railfence': {
            const rails = parseInt(document.getElementById('key-rails')?.value);
            if (isNaN(rails) || rails < 2) {
                hideLoading();
                alert('Please enter number of rails (2+)');
                return;
            }
            plaintext = CryptoEngine.decryptRailFence(ciphertext, rails);
            break;
        }
        case 'columnar': {
            const key = document.getElementById('key-word')?.value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a keyword');
                return;
            }
            plaintext = CryptoEngine.decryptColumnar(ciphertext, key);
            break;
        }
        case 'double': {
            const key1 = document.getElementById('key-word1')?.value.toUpperCase();
            const key2 = document.getElementById('key-word2')?.value.toUpperCase();
            if (!key1 || !key2) {
                hideLoading();
                alert('Please enter both keywords');
                return;
            }
            plaintext = CryptoEngine.decryptDoubleTransposition(ciphertext, key1, key2);
            break;
        }
        case 'product': {
            // Get selected cipher types
            const subCipherType = elements.productSubCipher.value;
            const transCipherType = elements.productTransCipher.value;

            // Build substitution key based on selected cipher
            let subKey = {};
            try {
                switch (subCipherType) {
                    case 'additive':
                    case 'multiplicative':
                        subKey = { k: parseInt(document.getElementById('key-sub-k')?.value) };
                        if (isNaN(subKey.k)) throw new Error('Invalid key');
                        break;
                    case 'affine':
                        subKey = {
                            a: parseInt(document.getElementById('key-sub-a')?.value),
                            b: parseInt(document.getElementById('key-sub-b')?.value)
                        };
                        if (isNaN(subKey.a) || isNaN(subKey.b)) throw new Error('Invalid key');
                        break;
                    case 'vigenere':
                    case 'playfair':
                        subKey = { word: document.getElementById('key-sub-word')?.value.toUpperCase() };
                        if (!subKey.word) throw new Error('Invalid key');
                        break;
                    case 'hill':
                        subKey = {
                            matrix: [
                                [parseInt(document.getElementById('key-sub-a')?.value), parseInt(document.getElementById('key-sub-b')?.value)],
                                [parseInt(document.getElementById('key-sub-c')?.value), parseInt(document.getElementById('key-sub-d')?.value)]
                            ]
                        };
                        break;
                }
            } catch (e) {
                hideLoading();
                alert('Please enter valid substitution key');
                return null;
            }

            // Build transposition key based on selected cipher
            let transKey = {};
            try {
                switch (transCipherType) {
                    case 'railfence':
                        transKey = { rails: parseInt(document.getElementById('key-trans-rails')?.value) };
                        if (isNaN(transKey.rails) || transKey.rails < 2) throw new Error('Invalid rails');
                        break;
                    case 'columnar':
                        transKey = { word: document.getElementById('key-trans-word')?.value.toUpperCase() };
                        if (!transKey.word) throw new Error('Invalid key');
                        break;
                    case 'double':
                        transKey = {
                            word1: document.getElementById('key-trans-word1')?.value.toUpperCase(),
                            word2: document.getElementById('key-trans-word2')?.value.toUpperCase()
                        };
                        if (!transKey.word1 || !transKey.word2) throw new Error('Invalid keys');
                        break;
                }
            } catch (e) {
                hideLoading();
                alert('Please enter valid transposition key');
                return null;
            }

            const result = CryptoEngine.decryptProductCipherFlexible(ciphertext, subCipherType, subKey, transCipherType, transKey);

            const subName = subCipherType.charAt(0).toUpperCase() + subCipherType.slice(1);
            const transName = transCipherType.charAt(0).toUpperCase() + transCipherType.slice(1);

            elements.cipherResult.innerHTML = `
                <div style="margin-bottom: 0.5rem;">After ${transName} Reverse: ${result.afterTransposition}</div>
                <div>Final Plaintext: ${result.plaintext}</div>
            `;
            elements.encryptionOutput.querySelector('h3').textContent = `Decrypted (${subName} + ${transName})`;
            elements.encryptionOutput.classList.remove('hidden');
            elements.emptyState.classList.add('hidden');
            return result.plaintext;
        }
        case 'autokey': {
            const k = parseInt(document.getElementById('key-k')?.value);
            if (isNaN(k) || k < 0 || k > 25) {
                hideLoading();
                alert('Please enter a valid initial key (0-25)');
                return null;
            }
            const result = CryptoEngine.decryptAutokey(ciphertext, k);
            plaintext = result.plaintext;
            break;
        }
        case 'monoalphabetic': {
            const keyword = document.getElementById('key-word')?.value.toUpperCase();
            if (!keyword) {
                hideLoading();
                alert('Please enter a keyword');
                return null;
            }
            const keyAlphabet = CryptoEngine.generateMonoalphabeticKey(keyword);
            plaintext = CryptoEngine.decryptMonoalphabetic(ciphertext, keyAlphabet);
            break;
        }
        case 'vernam': {
            const key = document.getElementById('key-word')?.value.toUpperCase();
            if (!key) {
                hideLoading();
                alert('Please enter a key');
                return null;
            }
            try {
                const result = CryptoEngine.decryptVernam(ciphertext, key);
                plaintext = result.plaintext;
            } catch (e) {
                hideLoading();
                alert(e.message);
                return null;
            }
            break;
        }
        case 'simple-trans': {
            const cols = parseInt(document.getElementById('key-cols')?.value);
            if (isNaN(cols) || cols < 2 || cols > 10) {
                hideLoading();
                alert('Number of columns must be between 2 and 10');
                return null;
            }
            plaintext = CryptoEngine.decryptSimpleTransposition(ciphertext, cols);
            break;
        }
    }

    if (!plaintext) {
        hideLoading();
        alert('Decryption failed - invalid key');
        return null;
    }

    // Show decryption result
    elements.cipherResult.textContent = plaintext;
    elements.encryptionOutput.querySelector('h3').textContent = 'Decrypted Plaintext';
    elements.encryptionOutput.classList.remove('hidden');
    elements.emptyState.classList.add('hidden');

    addToHistory('DECRYPT', ciphertext, plaintext);
    return plaintext; // Return for chaining
}

// ==================== WORKER MANAGEMENT ====================
let activeWorker = null;

function terminateWorker() {
    if (activeWorker) {
        activeWorker.terminate();
        activeWorker = null;
    }
}

function executeCrack() {
    const ciphertext = CryptoEngine.cleanText(elements.ciphertextInput.value);

    if (!ciphertext) {
        hideLoading();
        alert('Please enter ciphertext to crack');
        return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
        terminateWorker();
        activeWorker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });

        // Setup options for product cipher
        const options = {
            subType: elements.productSubCipher.value,
            transType: elements.productTransCipher.value
        };

        // Listen for messages
        activeWorker.onmessage = function (e) {
            const data = e.data;

            if (data.type === 'progress') {
                updateLoadingStatus(data.message);
            } else if (data.type === 'complete') {
                addToHistory('CRACK', ciphertext, data.results);
                displayResults(data.results);
                hideLoading(); // Hide loading after results are displayed
                resolve();
            } else if (data.type === 'error') {
                hideLoading(); // Hide loading on error
                reject(new Error(data.message));
            }
        };

        activeWorker.onerror = function (e) {
            hideLoading(); // Hide loading on worker error
            reject(new Error('Worker error: ' + e.message));
        };

        // Start job
        activeWorker.postMessage({
            type: 'crack',
            cipher: state.cipherType,
            text: ciphertext,
            options: options
        });
    });
}

function updateLoadingStatus(msg) {
    const loadingText = elements.loadingState.querySelector('.loading-text');
    if (loadingText) loadingText.textContent = msg;
}

// ==================== DISPLAY RESULTS ====================
function displayResults(results) {
    if (!results || results.length === 0) {
        elements.emptyState.innerHTML = '<h3>No candidates found</h3>';
        elements.emptyState.classList.remove('hidden');
        elements.topCandidates.classList.add('hidden');
        elements.allResultsToggle.classList.add('hidden');
        return;
    }

    elements.emptyState.classList.add('hidden');
    elements.topCandidates.classList.remove('hidden');
    elements.allResultsToggle.classList.remove('hidden');

    // Top 5 candidates
    const topResults = results.slice(0, 5);
    elements.candidatesContainer.innerHTML = topResults.map((result, index) => `
        <div class="candidate-card">
            <div class="candidate-rank">#${index + 1}</div>
            <div class="candidate-info">
                <div class="candidate-key">${result.keyDisplay}</div>
                <div class="candidate-text">${result.plaintext}</div>
            </div>
            <div class="candidate-score">
                <div class="score-value ${getConfidenceClass(result.confidence)}">${result.confidence}%</div>
                <div class="score-label">Confidence</div>
            </div>
        </div>
    `).join('');

    // All results
    elements.allResultsContainer.innerHTML = results.map(result => `
        <div class="result-row">
            <span class="key">${result.keyDisplay}</span>
            <span class="plaintext">${result.plaintext}</span>
            <span class="score">${result.confidence}%</span>
        </div>
    `).join('');
}

function getConfidenceClass(confidence) {
    if (confidence >= 60) return 'confidence-high';
    if (confidence >= 30) return 'confidence-medium';
    return 'confidence-low';
}

// ==================== UI HELPERS ====================
function showLoading() {
    elements.emptyState.classList.add('hidden');
    elements.topCandidates.classList.add('hidden');
    elements.allResultsToggle.classList.add('hidden');
    elements.allResults.classList.add('hidden');
    elements.loadingState.classList.remove('hidden');
}

function hideLoading() {
    elements.loadingState.classList.add('hidden');
}

function toggleAllResults() {
    const isHidden = elements.allResults.classList.toggle('hidden');
    elements.toggleAllBtn.textContent = isHidden ? 'Show All Results' : 'Hide All Results';
}

function clearAll() {
    elements.plaintextInput.value = '';
    elements.ciphertextInput.value = '';
    elements.encryptionOutput.classList.add('hidden');
    elements.topCandidates.classList.add('hidden');
    elements.allResultsToggle.classList.add('hidden');
    elements.allResults.classList.add('hidden');
    elements.emptyState.classList.remove('hidden');

    // Reset key inputs
    const keyInputElements = elements.keyInputs.querySelectorAll('input');
    keyInputElements.forEach(input => input.value = '');
}

// ==================== STYLE FOR HIDDEN CLASS ====================
const style = document.createElement('style');
style.textContent = '.hidden { display: none !important; }';
document.head.appendChild(style);

// ==================== THEME TOGGLE ====================
function toggleTheme() {
    console.log('toggleTheme called');
    const body = document.body;
    const themeIcon = document.getElementById('theme-icon');
    const currentTheme = body.getAttribute('data-theme');
    console.log('Current theme:', currentTheme);

    if (currentTheme === 'dark') {
        body.removeAttribute('data-theme');
        if (themeIcon) themeIcon.textContent = 'DARK MODE';
        localStorage.setItem('theme', 'light');
        console.log('Switched to light mode');
    } else {
        body.setAttribute('data-theme', 'dark');
        if (themeIcon) themeIcon.textContent = 'LIGHT MODE';
        localStorage.setItem('theme', 'dark');
        console.log('Switched to dark mode');
    }
}

function loadSavedTheme() {
    const savedTheme = localStorage.getItem('theme');
    const themeIcon = document.getElementById('theme-icon');
    console.log('Loading saved theme:', savedTheme);

    if (savedTheme === 'dark') {
        document.body.setAttribute('data-theme', 'dark');
        if (themeIcon) themeIcon.textContent = 'LIGHT MODE';
    } else {
        document.body.removeAttribute('data-theme');
        if (themeIcon) themeIcon.textContent = 'DARK MODE';
    }
}

// ==================== START APP ====================
document.addEventListener('DOMContentLoaded', init);
