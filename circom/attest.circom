pragma circom 2.1.6;

include "merkleTree.circom";
include "verifyKeySchnorrGroup.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";

// Prove being a member of a valid Merkle tree
template Attest(levels) {
    signal input root;
    signal input devAddr;
    signal input response;
    signal input challenge;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // Schnorr Signature
    signal input enabled;
    signal input message;
    signal input pubX;
    signal input pubY;
    signal input S;
    signal input e;

    signal hashValue;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== devAddr;
    hasher.inputs[1] <== challenge;
    hasher.inputs[2] <== response;
    hashValue <== hasher.out;
    
    // No need to check leaf === hashValue
    // This constraint will be passed if-and-only-if the hashValue
    // actually belongs to the Merkle tree of the given root,
    // which is checked in MerkleTreeChecker component :)
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== hashValue;
    tree.root <== root;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    component schnorr_verifier = Schnorr(
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
        );

    schnorr_verifier.enabled <== enabled;
    schnorr_verifier.message <== message;
    schnorr_verifier.S <== S;
    schnorr_verifier.e <== e;
    schnorr_verifier.pubX <== pubX;
    schnorr_verifier.pubY <== pubY;

    1 === schnorr_verifier.out;
}

component main {public[enabled, pubX, pubY]} = Attest(20);