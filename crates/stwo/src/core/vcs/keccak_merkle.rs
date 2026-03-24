use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use super::keccak_hash::KeccakHash;
use crate::core::channel::{KeccakChannel, MerkleChannel};
use crate::core::fields::m31::BaseField;
use crate::core::vcs::keccak_hash::KeccakHasher;
use crate::core::vcs::MerkleHasher;
use crate::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;

pub const LEAF_PREFIX: [u8; 64] = [
    b'l', b'e', b'a', b'f', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];
pub const NODE_PREFIX: [u8; 64] = [
    b'n', b'o', b'd', b'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct KeccakMerkleHasher;

impl MerkleHasher for KeccakMerkleHasher {
    type Hash = KeccakHash;

    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash {
        let mut hasher = Keccak256::new();

        // Use same prefix structure as Blake2s for compatibility
        if let Some((left_child, right_child)) = children_hashes {
            hasher.update(NODE_PREFIX);
            hasher.update(left_child.as_ref());
            hasher.update(right_child.as_ref());
        } else {
            hasher.update(LEAF_PREFIX);
        }

        for value in column_values {
            hasher.update(value.0.to_le_bytes());
        }

        let result = KeccakHash(hasher.finalize().into());
        // if children_hashes.is_some() {
        //     println!("  -> Node hash: 0x{}", hex::encode(result.0));
        // } else {
        //     println!("  -> Leaf hash: 0x{}", hex::encode(result.0));
        // }
        result
    }
}

#[derive(Default)]
pub struct KeccakMerkleChannel;

impl MerkleChannel for KeccakMerkleChannel {
    type C = KeccakChannel;
    type H = KeccakHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        channel.update_digest(super::keccak_hash::KeccakHasher::concat_and_hash(
            &channel.digest(),
            &root,
        ));
    }
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use crate::core::fields::m31::BaseField;
    use crate::core::vcs::keccak_hash::KeccakHash;
    use crate::core::vcs::keccak_merkle::KeccakMerkleHasher;
    use crate::core::vcs::test_utils::prepare_merkle;
    use crate::core::vcs::verifier::MerkleVerificationError;
    use crate::core::vcs::MerkleHasher;

    #[test]
    fn test_merkle_success_keccak() {
        let (queries, decommitment, values, verifier) = prepare_merkle::<KeccakMerkleHasher>();

        verifier.verify(&queries, values, decommitment).unwrap();
    }

    #[test]
    fn test_merkle_invalid_witness_keccak() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle::<KeccakMerkleHasher>();
        decommitment.hash_witness[4] = KeccakHash::default();

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::RootMismatch
        );
    }

    #[test]
    fn test_merkle_witness_too_short_keccak() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle::<KeccakMerkleHasher>();
        decommitment.hash_witness.pop();

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooShort
        );
    }

    #[test]
    fn test_merkle_witness_too_long_keccak() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle::<KeccakMerkleHasher>();
        decommitment.hash_witness.push(KeccakHash::default());

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooLong
        );
    }

    #[test]
    fn test_hash_comparison_with_blake2s() {
        use crate::core::vcs::blake2_merkle::Blake2sMerkleHasher;

        // Create test data
        let values = vec![BaseField::from(1), BaseField::from(2), BaseField::from(3)];

        // Hash with both implementations
        let keccak_hash = KeccakMerkleHasher::hash_node(None, &values);
        let blake2s_hash = Blake2sMerkleHasher::hash_node(None, &values);

        // Hashes should be different (different algorithms)
        assert_ne!(keccak_hash.0.to_vec(), blake2s_hash.0.to_vec());

        // But both should be non-zero
        assert_ne!(keccak_hash.0, [0u8; 32]);
        assert_ne!(blake2s_hash.0, [0u8; 32]);
    }

    #[test]
    fn test_leaf_vs_node_hashing() {
        let values = vec![BaseField::from(42), BaseField::from(45)];

        // Hash as leaf (no children)
        let leaf_hash = KeccakMerkleHasher::hash_node(None, &values);

        // Hash as node (with dummy children)
        let dummy_child = leaf_hash;
        let node_hash = KeccakMerkleHasher::hash_node(Some((dummy_child, dummy_child)), &values);

        // Should produce different hashes due to different prefixes
        assert_ne!(leaf_hash, node_hash);
    }

    #[test]
    fn test_deterministic_hashing() {
        let values = vec![BaseField::from(123), BaseField::from(456)];

        let hash1 = KeccakMerkleHasher::hash_node(None, &values);
        let hash2 = KeccakMerkleHasher::hash_node(None, &values);

        // Should be deterministic
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_solidity() {
        let values = vec![BaseField::from(123), BaseField::from(456)];

        let hash1 = KeccakMerkleHasher::hash_node(None, &values);

        println!("KeccakMerkleHasher hash: 0x{}", hex::encode(hash1.0));
    }

    #[test]
    fn test_merkle_verification_with_real_data() {
        use std::collections::BTreeMap;

        use crate::core::vcs::verifier::{MerkleDecommitment, MerkleVerifier};

        // Root commitment from the test data
        let root = KeccakHash([
            4, 121, 99, 64, 148, 203, 210, 20, 206, 172, 78, 16, 210, 57, 165, 191, 43, 112, 218,
            76, 30, 105, 42, 243, 163, 248, 10, 7, 14, 185, 89, 73,
        ]);

        println!("Expected root: {:?}", root );

        // Hash witness - 7 hashes
        let hash_witness = vec![
            KeccakHash([
                171, 202, 64, 193, 28, 82, 54, 15, 9, 244, 176, 201, 231, 102, 70, 112, 123, 105,
                202, 187, 159, 59, 59, 243, 93, 8, 29, 32, 13, 220, 39, 50,
            ]),
            KeccakHash([
                171, 202, 64, 193, 28, 82, 54, 15, 9, 244, 176, 201, 231, 102, 70, 112, 123, 105,
                202, 187, 159, 59, 59, 243, 93, 8, 29, 32, 13, 220, 39, 50,
            ]),
            KeccakHash([
                171, 202, 64, 193, 28, 82, 54, 15, 9, 244, 176, 201, 231, 102, 70, 112, 123, 105,
                202, 187, 159, 59, 59, 243, 93, 8, 29, 32, 13, 220, 39, 50,
            ]),
            KeccakHash([
                171, 202, 64, 193, 28, 82, 54, 15, 9, 244, 176, 201, 231, 102, 70, 112, 123, 105,
                202, 187, 159, 59, 59, 243, 93, 8, 29, 32, 13, 220, 39, 50,
            ]),
            KeccakHash([
                226, 185, 28, 138, 5, 106, 181, 97, 115, 99, 29, 172, 145, 153, 108, 61, 6, 240,
                157, 60, 38, 230, 163, 219, 40, 146, 83, 185, 149, 191, 191, 245,
            ]),
            KeccakHash([
                226, 185, 28, 138, 5, 106, 181, 97, 115, 99, 29, 172, 145, 153, 108, 61, 6, 240,
                157, 60, 38, 230, 163, 219, 40, 146, 83, 185, 149, 191, 191, 245,
            ]),
            KeccakHash([
                154, 187, 40, 169, 116, 29, 146, 43, 248, 137, 213, 95, 30, 111, 34, 184, 85, 157,
                34, 154, 121, 162, 223, 175, 245, 185, 16, 179, 47, 125, 179, 218,
            ]),
        ];

        // Empty column witness (all values are queried, not from witness)
        let column_witness = vec![];

        let decommitment: MerkleDecommitment<KeccakMerkleHasher> = MerkleDecommitment {
            hash_witness,
            column_witness,
        };

        println!("Decommitment prepared.");
        println!("Decommitment: {:?}", decommitment);

        // Query positions: [4, 5, 13] at log_domain_size: 5
        let mut queries: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
        queries.insert(4, vec![2, 3, 6, 7]);
        queries.insert(5, vec![4, 5, 12, 13]);

        // Column configuration - based on query_evals_by_column structure:
        // Column 0: 3 values (positions 4, 5, 13)
        // Column 1: 2 values (positions 4, 5, 13 - but only 2 values?)
        // Actually, looking at the data, it seems we have different columns
        // For now, let's assume we have columns at log_size 5
        let column_log_sizes = vec![5, 5, 5, 5, 4, 4, 4, 4]; // Single column of size 2^5 = 32

        // Queried values - all zeros based on query_evals_by_column
        // Each position has QM31 values (4 BaseField elements)
        // Position 4: (0 + 0i) + (0 + 0i)u = [0, 0, 0, 0]
        // Position 5: (0 + 0i) + (0 + 0i)u = [0, 0, 0, 0]
        // Position 13: (0 + 0i) + (0 + 0i)u = [0, 0, 0, 0]
        let queried_values: Vec<BaseField> = vec![
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0), // Position 4
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0), // Position 5
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0), // Position 13
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
            BaseField::from(0),
        ];

        println!("Queried values prepared: {:?}", queried_values);

        let verifier: MerkleVerifier<KeccakMerkleHasher> =
            MerkleVerifier::new(root, column_log_sizes);

        println!("Queries prepared: {:?}", queries);    
        
        // Enable detailed logging for verification
        println!("\n=== Starting Merkle verification ===");
        
        // Verify the decommitment
        let result = verifier.verify(&queries, queried_values, decommitment);

        match &result {
            Ok(_) => println!("✓ Merkle verification PASSED!"),
            Err(e) => println!("✗ Merkle verification FAILED: {:?}", e),
        }

        // Assert verification succeeds
        result.unwrap();

        println!("Test completed successfully!");
        println!("Root: 0x{}", hex::encode(root.0));
    }
}
