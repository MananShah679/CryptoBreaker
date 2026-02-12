/**
 * Automated test script for Merkle Tree implementation
 * Run with: node test_merkle.mjs
 */

import { MerkleTree } from './src/lib/merkle.js';

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

async function runTests() {
    console.log('\n=== MERKLE TREE TESTS ===');

    // Test SHA-256
    {
        const hash = await MerkleTree.sha256('hello');
        // SHA256('hello') = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert(hash === '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', 'SHA-256("hello")', `got ${hash}`);
    }

    // Test Double SHA-256
    {
        const hash = await MerkleTree.doubleSha256('hello');
        // SHA256(SHA256('hello'))
        // SHA256('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' as bytes)
        // Expected: 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50
        assert(hash === '9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50', 'Double SHA-256("hello")', `got ${hash}`);
    }

    // Test Tree Construction (Even number of leaves)
    {
        const txs = ['tx1', 'tx2', 'tx3', 'tx4'];
        const tree = await MerkleTree.buildMerkleTree(txs);

        assert(tree.leaves.length === 4, 'Leaves count correct (4)');
        assert(tree.levels.length === 3, 'Tree height correct (3 levels including leaves)');
        assert(tree.root.length === 64, 'Root hash length correct');

        // Manual verification
        const leaf0 = await MerkleTree.doubleSha256('tx1');
        const leaf1 = await MerkleTree.doubleSha256('tx2');
        const leaf2 = await MerkleTree.doubleSha256('tx3');
        const leaf3 = await MerkleTree.doubleSha256('tx4');

        const parent01 = await MerkleTree.doubleSha256(leaf0 + leaf1);
        const parent23 = await MerkleTree.doubleSha256(leaf2 + leaf3);
        const root = await MerkleTree.doubleSha256(parent01 + parent23);

        assert(tree.root === root, 'Root matches manual calculation', `got ${tree.root}, expected ${root}`);
    }

    // Test Tree Construction (Odd number of leaves)
    {
        const txs = ['tx1', 'tx2', 'tx3'];
        const tree = await MerkleTree.buildMerkleTree(txs);

        assert(tree.leaves.length === 3, 'Leaves count correct (3)');
        // Level 0: [L1, L2, L3]
        // Level 1: [Hash(L1+L2), Hash(L3+L3)] (because it duplicates)
        // Level 2: [Hash(P1+P2)]

        const leaf0 = await MerkleTree.doubleSha256('tx1');
        const leaf1 = await MerkleTree.doubleSha256('tx2');
        const leaf2 = await MerkleTree.doubleSha256('tx3');

        const parent01 = await MerkleTree.doubleSha256(leaf0 + leaf1);
        const parent22 = await MerkleTree.doubleSha256(leaf2 + leaf2); // Duplicated
        const root = await MerkleTree.doubleSha256(parent01 + parent22);

        assert(tree.root === root, 'Root matches manual calculation (odd leaves)', `got ${tree.root}, expected ${root}`);
    }

    // Test Proof Generation & Verification
    {
        const txs = ['a', 'b', 'c', 'd', 'e'];
        const tree = await MerkleTree.buildMerkleTree(txs);

        // Verify 'c' (index 2)
        const proof = MerkleTree.getMerkleProof(tree, 2);
        assert(proof.proof.length > 0, 'Proof generated');

        const leafHash = await MerkleTree.doubleSha256('c');
        const verification = await MerkleTree.verifyMerkleProof(leafHash, proof.proof, tree.root);

        assert(verification.valid === true, 'Proof verification passed');
        assert(verification.computedRoot === tree.root, 'Computed root matches tree root');

        // Test invalid proof
        const invalidProof = [...proof.proof];
        invalidProof[0] = { ...invalidProof[0], hash: '0'.repeat(64) }; // Tamper
        const failedVerification = await MerkleTree.verifyMerkleProof(leafHash, invalidProof, tree.root);
        assert(failedVerification.valid === false, 'Invalid proof correctly rejected');
    }

    // Test Steps Generation
    {
        const txs = ['A', 'B'];
        const tree = await MerkleTree.buildMerkleTree(txs);
        assert(tree.steps.length > 0, 'Steps generated');
        assert(tree.steps[0].step === 'Leaf Hashes (Double SHA-256)', 'First step is hashing leaves');
    }

    console.log('\n' + '='.repeat(50));
    console.log(`Results: ${pass} passed, ${fail} failed out of ${pass + fail} tests`);
    console.log('='.repeat(50));

    if (fail > 0) process.exit(1);
}

runTests().catch(err => {
    console.error('Test Error:', err);
    process.exit(1);
});
