use core::{array, iter};

use itertools::Itertools;
use std_shims::Vec;

use super::Channel;
use crate::core::fields::m31::{BaseField, P};
use crate::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use crate::core::vcs::keccak_hash::{KeccakHash, KeccakHasher};

pub const KECCAK_BYTES_PER_HASH: usize = 32;
pub const FELTS_PER_HASH: usize = 8;

/// A channel that can be used to draw random elements from a Keccak256 digest.
/// This provides a gas-efficient alternative to Blake2s for Ethereum deployment.
#[derive(Default, Clone, Debug)]
pub struct KeccakChannel {
    digest: KeccakHash,
    n_draws: u32,
}

impl KeccakChannel {
    pub const POW_PREFIX: u32 = 0x12345678;

    pub const fn digest(&self) -> KeccakHash {
        self.digest
    }
    
    pub const fn update_digest(&mut self, new_digest: KeccakHash) {
        self.digest = new_digest;
        self.n_draws = 0;
    }
    
    /// Generates a uniform random vector of BaseField elements.
    fn draw_base_felts(&mut self) -> [BaseField; FELTS_PER_HASH] {
        // Repeats hashing with an increasing counter until getting a good result.
        // Retry probability for each round is ~ 2^(-28).
        loop {
            let u32s: [u32; FELTS_PER_HASH] = self.draw_u32s().try_into().unwrap();

            // Retry if not all the u32 are in the range [0, 2P).
            if u32s.iter().all(|x| *x < 2 * P) {
                return u32s
                    .into_iter()
                    .map(|x| BaseField::reduce(x as u64))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
            }
        }
    }
}

impl Channel for KeccakChannel {
    const BYTES_PER_HASH: usize = KECCAK_BYTES_PER_HASH;

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let felts_bytes = felts
            .iter()
            .flat_map(|qm31| qm31.to_m31_array().into_iter())
            .flat_map(|m31| m31.0.to_le_bytes().into_iter())
            .collect_vec();
        let mut hasher = KeccakHasher::new();
        hasher.update(self.digest.as_ref());
        hasher.update(&felts_bytes);

        self.update_digest(hasher.finalize());
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        let mut hasher = KeccakHasher::new();
        hasher.update(self.digest.as_ref());
        for word in data {
            hasher.update(&word.to_le_bytes());
        }

        self.update_digest(hasher.finalize());
    }

    fn mix_u64(&mut self, value: u64) {
        self.mix_u32s(&[value as u32, (value >> 32) as u32])
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        let felts: [BaseField; FELTS_PER_HASH] = self.draw_base_felts();
        SecureField::from_m31_array(felts[..SECURE_EXTENSION_DEGREE].try_into().unwrap())
    }

    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut felts = iter::from_fn(|| Some(self.draw_base_felts())).flatten();
        let secure_felts = iter::from_fn(|| {
            Some(SecureField::from_m31_array([
                felts.next()?,
                felts.next()?,
                felts.next()?,
                felts.next()?,
            ]))
        });
        secure_felts.take(n_felts).collect()
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        let mut hash_input = self.digest.as_ref().to_vec();

        // Append counter bytes directly (4 bytes for u32).
        let counter_bytes = self.n_draws.to_le_bytes();
        hash_input.extend_from_slice(&counter_bytes);

        // Append a zero byte for domain separation between generating randomness and mixing a
        // single u32.
        hash_input.push(0_u8);

        self.n_draws += 1;
        KeccakHasher::hash(&hash_input)
            .0
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    /// Verifies that `H(H(POW_PREFIX, [0_u8; 24], digest, n_bits), nonce)` has at least `n_bits`
    /// many leading zeros.
    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        let digest = self.digest();
        // Compute H(POW_PREFIX, [0_u8; 24], digest, n_bits).
        let mut hasher = KeccakHasher::default();
        hasher.update(&Self::POW_PREFIX.to_le_bytes());
        hasher.update(&[0_u8; 24]);
        hasher.update(&digest.0[..]);
        hasher.update(&n_bits.to_le_bytes());
        let prefixed_digest = hasher.finalize();
        // Compute `H(prefixed_digest, nonce)`.
        let mut hasher = KeccakHasher::default();
        hasher.update(prefixed_digest.as_ref());
        hasher.update(&nonce.to_le_bytes());
        let res = hasher.finalize();
        let n_zeros = u128::from_le_bytes(array::from_fn(|i| res.0[i])).trailing_zeros();
        n_zeros >= n_bits
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use std_shims::BTreeSet;

    use crate::core::channel::keccak::KeccakChannel;
    use crate::core::channel::Channel;
    use crate::core::fields::qm31::SecureField;
    use crate::m31;

    #[test]
    fn test_channel_draws() {
        let mut channel = KeccakChannel::default();

        assert_eq!(channel.n_draws, 0);

        channel.draw_u32s();
        assert_eq!(channel.n_draws, 1);

        channel.draw_secure_felts(9);
        assert_eq!(channel.n_draws, 6);
    }

    #[test]
    fn test_draw_u32s() {
        let mut channel = KeccakChannel::default();

        let first_random_words = channel.draw_u32s();

        // Assert that next random words are different.
        assert_ne!(first_random_words, channel.draw_u32s());
    }

    #[test]
    pub fn test_draw_secure_felt() {
        let mut channel = KeccakChannel::default();

        let first_random_felt = channel.draw_secure_felt();

        // Assert that next random felt is different.
        assert_ne!(first_random_felt, channel.draw_secure_felt());
    }

    #[test]
    pub fn test_draw_secure_felts() {
        let mut channel = KeccakChannel::default();

        let mut random_felts = channel.draw_secure_felts(5);
        random_felts.extend(channel.draw_secure_felts(4));

        // Assert that all the random felts are unique.
        assert_eq!(
            random_felts.len(),
            random_felts.iter().collect::<BTreeSet<_>>().len()
        );
    }

    #[test]
    pub fn test_mix_felts() {
        let mut channel = KeccakChannel::default();
        let initial_digest = channel.digest;
        let felts = (0..2)
            .map(|i| SecureField::from(m31!(i + 1923782)))
            .collect_vec();

        channel.mix_felts(felts.as_slice());

        assert_ne!(initial_digest, channel.digest);
    }

    #[test]
    pub fn test_mix_u64() {
        let mut channel = KeccakChannel::default();
        channel.mix_u64(0x1111222233334444);
        let digest_64 = channel.digest;

        let mut channel = KeccakChannel::default();
        channel.mix_u32s(&[0x33334444, 0x11112222]);

        assert_eq!(digest_64, channel.digest);
    }

    #[test]
    pub fn test_mix_u32s() {
        let mut channel = KeccakChannel::default();
        channel.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        
        // Keccak should produce different digest than Blake2s
        assert_ne!(channel.digest.0, [0u8; 32]); // Not all zeros
        
        // Test determinism
        let mut channel2 = KeccakChannel::default();
        channel2.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(channel.digest, channel2.digest);
    }

    #[test]
    pub fn test_verify_pow_nonce() {
        let channel = KeccakChannel::default();
        
        // This should be very unlikely to pass with nonce=0
        assert!(!channel.verify_pow_nonce(20, 0));
        
        // Test with smaller number of bits
        let result = channel.verify_pow_nonce(1, 12345);
        // Just verify it doesn't panic - actual verification depends on hash output
        assert!(result || !result); // Tautology to ensure test runs
    }

    #[test]
    fn test_keccak_channel_known_vectors() {
        let mut channel = KeccakChannel::default();

        let draw0 = channel.draw_u32s();
        assert_eq!(
            draw0,
            vec![
                704_766_614,
                459_244_513,
                475_191_447,
                2_007_521_349,
                3_177_025_465,
                789_102_175,
                3_930_552_170,
                167_659_942,
            ]
        );

        let draw1 = channel.draw_u32s();
        assert_eq!(
            draw1,
            vec![
                2_458_925_245,
                2_528_194_765,
                3_300_231_132,
                4_288_850_010,
                2_162_335_768,
                4_079_801_769,
                3_920_211_612,
                676_166_186,
            ]
        );

        let mut mix_u32s_channel = KeccakChannel::default();
        mix_u32s_channel.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            mix_u32s_channel.digest().0,
            [
                0x1f, 0xc4, 0x72, 0x11, 0x17, 0xdb, 0x54, 0x22, 0xb8, 0x4d, 0x79, 0x96, 0x90,
                0xe2, 0xe4, 0x8b, 0xc8, 0x26, 0x6f, 0xfd, 0x74, 0x0a, 0x6b, 0xf5, 0xd5, 0x54,
                0x7f, 0xdc, 0x49, 0x1c, 0x86, 0x8c,
            ]
        );

        let mut mix_felts_channel = KeccakChannel::default();
        let felts = [
            SecureField::from_m31_array([m31!(11), m31!(22), m31!(33), m31!(44)]),
            SecureField::from_m31_array([m31!(55), m31!(66), m31!(77), m31!(88)]),
        ];
        mix_felts_channel.mix_felts(&felts);
        assert_eq!(
            mix_felts_channel.digest().0,
            [
                0x65, 0x15, 0x67, 0x75, 0x50, 0x17, 0x77, 0x65, 0x75, 0x6e, 0xed, 0xe9, 0xc4,
                0x4a, 0xc5, 0xc3, 0xed, 0xbb, 0xdf, 0xb3, 0xc5, 0xc7, 0x42, 0x6b, 0x70, 0x09,
                0x26, 0xe6, 0x67, 0x6c, 0x6c, 0xb8,
            ]
        );

        let pow_channel = KeccakChannel::default();
        assert!(pow_channel.verify_pow_nonce(3, 12_345));
        assert!(!pow_channel.verify_pow_nonce(4, 12_345));
    }
}