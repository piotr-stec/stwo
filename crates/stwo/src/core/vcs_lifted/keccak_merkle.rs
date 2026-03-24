use super::merkle_hasher::MerkleHasherLifted;
use crate::core::channel::{KeccakChannel, MerkleChannel};
use crate::core::fields::m31::BaseField;
use crate::core::vcs::keccak_hash::{KeccakHash, KeccakHasher};

pub type KeccakMerkleHasher = KeccakHasher;

impl MerkleHasherLifted for KeccakHasher {
    type Hash = KeccakHash;

    fn hash_children(children_hashes: (Self::Hash, Self::Hash)) -> Self::Hash {
        let (left_child, right_child) = children_hashes;
        KeccakHasher::concat_and_hash(&left_child, &right_child)
    }

    fn update_leaf(&mut self, column_values: &[BaseField]) {
        column_values
            .iter()
            .for_each(|x| self.update(&x.0.to_le_bytes()));
    }

    fn finalize(self) -> Self::Hash {
        self.finalize()
    }
}

#[derive(Default)]
pub struct KeccakMerkleChannel;

impl MerkleChannel for KeccakMerkleChannel {
    type C = KeccakChannel;
    type H = KeccakMerkleHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasherLifted>::Hash) {
        channel.update_digest(KeccakHasher::concat_and_hash(&channel.digest(), &root));
    }
}
