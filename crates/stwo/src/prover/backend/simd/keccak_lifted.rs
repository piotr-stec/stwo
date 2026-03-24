use itertools::Itertools;

use super::SimdBackend;
use crate::core::fields::m31::BaseField;
use crate::core::vcs::keccak_hash::{KeccakHash, KeccakHasher};
use crate::prover::backend::{Col, Column, ColumnOps, CpuBackend};
use crate::prover::vcs_lifted::ops::MerkleOpsLifted;

impl ColumnOps<KeccakHash> for SimdBackend {
    type Column = Vec<KeccakHash>;

    fn bit_reverse_column(_column: &mut Self::Column) {
        unimplemented!()
    }
}

/// TODO: replace with a true SIMD implementation.
impl MerkleOpsLifted<KeccakHasher> for SimdBackend {
    fn build_leaves(
        columns: &[&Col<Self, BaseField>],
        lifting_log_size: u32,
    ) -> Col<Self, KeccakHash> {
        let cpu_cols = columns.iter().map(|column| column.to_cpu()).collect_vec();
        <CpuBackend as MerkleOpsLifted<KeccakHasher>>::build_leaves(
            &cpu_cols.iter().collect_vec(),
            lifting_log_size,
        )
    }

    fn build_next_layer(prev_layer: &Col<Self, KeccakHash>) -> Col<Self, KeccakHash> {
        <CpuBackend as MerkleOpsLifted<KeccakHasher>>::build_next_layer(prev_layer)
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::core::fields::m31::{BaseField, M31};
    use crate::core::vcs::keccak_hash::KeccakHash;
    use crate::core::vcs::keccak_hash::KeccakHasher;
    use crate::prover::backend::simd::column::BaseColumn;
    use crate::prover::backend::simd::SimdBackend;
    use crate::prover::backend::CpuBackend;
    use crate::prover::vcs_lifted::ops::MerkleOpsLifted;
    use crate::prover::vcs_lifted::prover::MerkleProverLifted;

    #[test]
    fn test_build_next_layer() {
        const LOG_SIZE: u32 = 6;
        let layer: Vec<KeccakHash> = (0u32..1 << (LOG_SIZE + 1))
            .map(|i| KeccakHasher::hash(&i.to_le_bytes()))
            .collect();
        assert_eq!(
            <CpuBackend as MerkleOpsLifted<KeccakHasher>>::build_next_layer(&layer),
            <SimdBackend as MerkleOpsLifted<KeccakHasher>>::build_next_layer(&layer)
        );
    }

    #[test]
    fn test_keccak_merkle_commit() {
        const MAX_LOG_N_ROWS: u32 = 9;
        const N_COLS: u32 = 64;
        let cols: Vec<Vec<BaseField>> = (0..N_COLS)
            .map(|i| {
                (0..1 << MAX_LOG_N_ROWS)
                    .map(|j| M31::from(100 * i + j))
                    .collect_vec()
            })
            .collect();
        let cols_simd: Vec<BaseColumn> = cols.iter().map(|c| BaseColumn::from_cpu(c)).collect();

        let cpu_root = MerkleProverLifted::<CpuBackend, KeccakHasher>::commit(
            cols.iter().collect(),
            MAX_LOG_N_ROWS,
        )
        .root();
        let simd_root = MerkleProverLifted::<SimdBackend, KeccakHasher>::commit(
            cols_simd.iter().collect(),
            MAX_LOG_N_ROWS,
        )
        .root();

        assert_eq!(cpu_root, simd_root);
    }
}
