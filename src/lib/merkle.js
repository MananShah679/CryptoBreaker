/**
 * Merkle Tree Module
 * Bitcoin-style Merkle Tree using double SHA-256
 * With transaction inclusion proofs and step-by-step visualization
 */

// ==================== SHA-256 ====================

/**
 * SHA-256 hash using Web Crypto API
 * Returns hex string
 */
async function sha256(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * SHA-256 hash of raw bytes (for double hashing)
 */
async function sha256Bytes(hexString) {
    const bytes = new Uint8Array(hexString.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Double SHA-256: SHA256(SHA256(data)) — as used in Bitcoin
 */
async function doubleSha256(message) {
    const firstHash = await sha256(message);
    const secondHash = await sha256Bytes(firstHash);
    return secondHash;
}

/**
 * Concatenate two hex hashes as raw bytes and double-SHA256 the result.
 * Bitcoin concatenates raw 32-byte buffers, NOT hex strings.
 */
async function doubleSha256Concat(hexA, hexB) {
    const bytesA = new Uint8Array(hexA.match(/.{2}/g).map(b => parseInt(b, 16)));
    const bytesB = new Uint8Array(hexB.match(/.{2}/g).map(b => parseInt(b, 16)));
    const combined = new Uint8Array(bytesA.length + bytesB.length);
    combined.set(bytesA, 0);
    combined.set(bytesB, bytesA.length);
    // First SHA-256 on raw concatenated bytes
    const hash1 = await crypto.subtle.digest('SHA-256', combined);
    // Second SHA-256 on the raw hash bytes
    const hash2 = await crypto.subtle.digest('SHA-256', hash1);
    const hashArray = Array.from(new Uint8Array(hash2));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ==================== MERKLE TREE ====================

/**
 * Build a Merkle Tree from an array of transactions
 * Returns { root, levels, leaves } where:
 *   - root: the Merkle root hash
 *   - levels: array of arrays (bottom to top), each level contains hashes
 *   - leaves: the leaf hashes (double SHA-256 of each transaction)
 */
async function buildMerkleTree(transactions) {
    if (transactions.length === 0) {
        return { root: null, levels: [], leaves: [] };
    }

    const steps = [];

    // Step 1: Hash each transaction with double SHA-256
    const leaves = [];
    for (const tx of transactions) {
        const hash = await doubleSha256(tx);
        leaves.push(hash);
    }

    steps.push({
        step: 'Leaf Hashes (Double SHA-256)',
        description: 'Hash each transaction using SHA256(SHA256(tx))',
        hashes: transactions.map((tx, i) => ({
            transaction: tx,
            hash: leaves[i],
            label: `H(T${i + 1})`
        }))
    });

    const levels = [leaves.slice()]; // Level 0 = leaves
    let currentLevel = leaves.slice();

    let levelNum = 1;
    // Step 2: Build tree bottom-up
    while (currentLevel.length > 1) {
        const nextLevel = [];
        const levelDetails = [];

        // If odd number, duplicate last hash (Bitcoin convention)
        if (currentLevel.length % 2 !== 0) {
            currentLevel.push(currentLevel[currentLevel.length - 1]);
        }

        for (let i = 0; i < currentLevel.length; i += 2) {
            const parentHash = await doubleSha256Concat(currentLevel[i], currentLevel[i + 1]);
            nextLevel.push(parentHash);
            levelDetails.push({
                left: currentLevel[i].substring(0, 16) + '...',
                right: currentLevel[i + 1].substring(0, 16) + '...',
                parent: parentHash.substring(0, 16) + '...',
                fullParent: parentHash
            });
        }

        steps.push({
            step: `Level ${levelNum} (${nextLevel.length} node${nextLevel.length > 1 ? 's' : ''})`,
            description: `Combine pairs: Hash(left || right)`,
            pairs: levelDetails
        });

        levels.push(nextLevel.slice());
        currentLevel = nextLevel;
        levelNum++;
    }

    return {
        root: currentLevel[0],
        levels,
        leaves,
        steps,
        transactions
    };
}

// ==================== MERKLE PROOF ====================

/**
 * Generate a Merkle Proof for a specific transaction index
 * Returns the sibling hashes and their positions (left/right)
 * needed to reconstruct the path from leaf to root
 */
function getMerkleProof(tree, txIndex) {
    if (txIndex < 0 || txIndex >= tree.leaves.length) {
        return { proof: [], valid: false, error: 'Invalid transaction index' };
    }

    const proof = [];
    let index = txIndex;

    for (let level = 0; level < tree.levels.length - 1; level++) {
        let currentLevelHashes = tree.levels[level].slice();

        // Duplicate last if odd (Bitcoin convention)
        if (currentLevelHashes.length % 2 !== 0) {
            currentLevelHashes.push(currentLevelHashes[currentLevelHashes.length - 1]);
        }

        const isLeft = (index % 2 === 0);
        const siblingIndex = isLeft ? index + 1 : index - 1;

        proof.push({
            hash: currentLevelHashes[siblingIndex],
            position: isLeft ? 'right' : 'left',
            level: level,
            siblingIndex: siblingIndex
        });

        index = Math.floor(index / 2);
    }

    return { proof, leafHash: tree.leaves[txIndex], root: tree.root };
}

/**
 * Verify a Merkle Proof
 * Given a leaf hash and proof path, reconstruct and compare against root
 */
async function verifyMerkleProof(leafHash, proof, expectedRoot) {
    let currentHash = leafHash;
    const verificationSteps = [];

    for (const step of proof) {
        let leftHash, rightHash;
        if (step.position === 'left') {
            leftHash = step.hash;
            rightHash = currentHash;
            verificationSteps.push({
                operation: `Hash(sibling || current)`,
                left: step.hash.substring(0, 16) + '...',
                right: currentHash.substring(0, 16) + '...',
                fullLeft: step.hash,
                fullRight: currentHash,
                position: step.position
            });
        } else {
            leftHash = currentHash;
            rightHash = step.hash;
            verificationSteps.push({
                operation: `Hash(current || sibling)`,
                left: currentHash.substring(0, 16) + '...',
                right: step.hash.substring(0, 16) + '...',
                fullLeft: currentHash,
                fullRight: step.hash,
                position: step.position
            });
        }
        currentHash = await doubleSha256Concat(leftHash, rightHash);
        verificationSteps[verificationSteps.length - 1].result = currentHash.substring(0, 16) + '...';
    }

    return {
        computedRoot: currentHash,
        expectedRoot: expectedRoot,
        valid: currentHash === expectedRoot,
        steps: verificationSteps
    };
}

// ==================== EXPORTS ====================

export const MerkleTree = {
    sha256,
    doubleSha256,
    buildMerkleTree,
    getMerkleProof,
    verifyMerkleProof
};
