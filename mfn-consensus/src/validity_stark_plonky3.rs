//! B-12 first Plonky3 aggregation. Not consensus, and not a recursive verifier.
//!
//! One BabyBear STARK checks three phase-4a statements at once: the fee
//! basis-point split, and two depth-4 field-Merkle openings. The hash is four
//! rounds of `x -> (x + c)^7` on BabyBear. That is the same shape as
//! [`crate::validity_stark_merkle`], on a different field, so it does not
//! verify a Winterfell proof. Verifying one STARK inside another is later work.
//!
//! Values that do not fit in BabyBear are rejected. Path A and F-A stay as they are.
//!
//! B-39 local check: [`verify_aggregated_outputs`] takes the claimed outputs
//! and the parent-digest limbs and does not re-divide the fee or re-hash the
//! path. The parent limbs are public inputs, so a different parent does not
//! verify. This is not a gossip or header wire.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::rngs::SmallRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEPTH: usize = 4;
const ROUNDS: usize = 4;
const TRACE_LEN: usize = 8;
const RC: [u64; ROUNDS] = [3, 5, 7, 11];
const DOMAIN: u64 = 0x4d46;
const PAD: u64 = 2;

const P_FEE: usize = 0;
const P_BPS: usize = 1;
const P_TREASURY: usize = 2;
const P_PRODUCER: usize = 3;
const P_REM: usize = 4;
const P_LEAF_A: usize = 5;
const P_ROOT_A: usize = 6;
const P_INDEX_A: usize = 7;
const P_LEAF_B: usize = 8;
const P_ROOT_B: usize = 9;
const P_INDEX_B: usize = 10;
const P_PARENT: usize = 11;
const NUM_PUBLIC: usize = 15;

const C_CUR: usize = 0;
const C_SIB: usize = 1;
const C_BIT: usize = 2;
const C_LEFT: usize = 3;
const C_RIGHT: usize = 4;
const C_PLACE: usize = 5;
const C_ACC: usize = 6;
const C_CONTRIB: usize = 7;
const C_STEPS: usize = 8;
const C_ALIVE: usize = 9;
const C_INV: usize = 10;
const C_ROUNDS: usize = 11;
const PATH_SPAN: usize = C_ROUNDS + ROUNDS * 4;
const WIDTH: usize = PATH_SPAN * 2;

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<Val, Val, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Proof of the aggregated BabyBear statement.
pub type AggregatedProof = p3_uni_stark::Proof<MyConfig>;

/// Fee split plus two field-Merkle openings, all in one proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedClaim {
    /// Fee sum. `fee_sum * bps` must fit in BabyBear.
    pub fee_sum: u32,
    /// Treasury share in basis points, at most 10_000.
    pub fee_to_treasury_bps: u16,
    /// Integer quotient `fee_sum * bps / 10_000`.
    pub treasury_fee: u32,
    /// `fee_sum - treasury_fee`.
    pub producer_fee: u32,
    /// First tree, before padding.
    pub leaves_a: Vec<u32>,
    /// Index in the padded first tree.
    pub index_a: u32,
    /// Second tree, before padding.
    pub leaves_b: Vec<u32>,
    /// Index in the padded second tree.
    pub index_b: u32,
    /// Parent state digest as four BabyBear limbs.
    pub parent_digest: [u32; 4],
}

/// Claimed outputs for a light check. Roots and the fee split are not recomputed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedOutputs {
    /// Fee sum. `fee_sum * bps` must fit in BabyBear.
    pub fee_sum: u32,
    /// Treasury share in basis points, at most 10_000.
    pub fee_to_treasury_bps: u16,
    /// Claimed treasury share.
    pub treasury_fee: u32,
    /// Claimed producer share.
    pub producer_fee: u32,
    /// Claimed remainder, at most 9_999.
    pub remainder: u32,
    /// Opened leaf in the first tree.
    pub leaf_a: u32,
    /// Claimed first root.
    pub root_a: u32,
    /// Index in the padded first tree.
    pub index_a: u32,
    /// Opened leaf in the second tree.
    pub leaf_b: u32,
    /// Claimed second root.
    pub root_b: u32,
    /// Index in the padded second tree.
    pub index_b: u32,
    /// Parent state digest as four BabyBear limbs.
    pub parent_digest: [u32; 4],
}

/// Why an aggregated claim or proof was rejected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AggregateError {
    /// A number does not fit the BabyBear statement.
    #[error("aggregated claim does not fit the BabyBear statement")]
    OutOfRange,
    /// The split is not the integer quotient.
    #[error("aggregated split does not match integer division")]
    SplitDrift,
    /// Plonky3 rejected the proof for these public values.
    #[error("plonky3 proof invalid")]
    ProofInvalid,
    /// The witness bytes are not a version-1 envelope.
    #[error("aggregated witness bytes are malformed")]
    WitnessMalformed,
    /// The witness version is not the one this crate checks.
    #[error("aggregated witness version is not supported")]
    WitnessVersion,
}

/// BabyBear parent hash. Four seventh-power rounds.
pub fn babybear_merkle_compress(left: Val, right: Val) -> Val {
    round_state(left, right).1
}

/// Root after padding to 16 leaves with the value 2.
pub fn babybear_merkle_root(leaves: &[u32]) -> Result<u32, AggregateError> {
    Ok(as_u32(root_of(&padded(leaves)?)))
}

/// Prove the split and both openings. The claim's roots are the native roots.
pub fn prove_aggregated(claim: &AggregatedClaim) -> Result<AggregatedProof, AggregateError> {
    let public = public_values(claim)?;
    let trace = trace_for(claim, &public)?;
    Ok(prove(&config(), &AggregateAir, trace, &public))
}

/// Verify the aggregated proof. Does not re-hash the paths or divide the fee.
pub fn verify_aggregated(
    claim: &AggregatedClaim,
    proof: &AggregatedProof,
) -> Result<(), AggregateError> {
    let public = public_values(claim)?;
    verify(&config(), &AggregateAir, proof, &public).map_err(|_| AggregateError::ProofInvalid)
}

/// Light check. Does not divide the fee and does not hash the path.
///
/// `fee_sum * bps` must be below the BabyBear modulus and `remainder` must be
/// below 10_000, so the in-circuit equation has one integer solution. The
/// parent limbs are part of the public input vector.
pub fn verify_aggregated_outputs(
    outputs: &AggregatedOutputs,
    proof: &AggregatedProof,
) -> Result<(), AggregateError> {
    let public = public_from_outputs(outputs)?;
    verify(&config(), &AggregateAir, proof, &public).map_err(|_| AggregateError::ProofInvalid)
}

fn public_values(claim: &AggregatedClaim) -> Result<Vec<Val>, AggregateError> {
    if claim.fee_to_treasury_bps > 10_000 || claim.index_a >= 16 || claim.index_b >= 16 {
        return Err(AggregateError::OutOfRange);
    }
    let product = u128::from(claim.fee_sum) * u128::from(claim.fee_to_treasury_bps);
    let treasury = u32::try_from(product / 10_000).map_err(|_| AggregateError::OutOfRange)?;
    let rem = u32::try_from(product % 10_000).map_err(|_| AggregateError::OutOfRange)?;
    let producer = claim
        .fee_sum
        .checked_sub(treasury)
        .ok_or(AggregateError::SplitDrift)?;
    if treasury != claim.treasury_fee || producer != claim.producer_fee {
        return Err(AggregateError::SplitDrift);
    }
    if product >= u128::from(Val::ORDER_U64) {
        return Err(AggregateError::OutOfRange);
    }
    let tree_a = padded(&claim.leaves_a)?;
    let tree_b = padded(&claim.leaves_b)?;
    let root_a = root_of(&tree_a);
    let root_b = root_of(&tree_b);
    let mut public = vec![
        v(claim.fee_sum)?,
        v(u32::from(claim.fee_to_treasury_bps))?,
        v(claim.treasury_fee)?,
        v(claim.producer_fee)?,
        v(rem)?,
        tree_a[claim.index_a as usize],
        root_a,
        v(claim.index_a)?,
        tree_b[claim.index_b as usize],
        root_b,
        v(claim.index_b)?,
    ];
    debug_assert_eq!(public.len(), P_PARENT);
    public.extend([
        v(claim.parent_digest[0])?,
        v(claim.parent_digest[1])?,
        v(claim.parent_digest[2])?,
        v(claim.parent_digest[3])?,
    ]);
    Ok(public)
}

fn public_from_outputs(outputs: &AggregatedOutputs) -> Result<Vec<Val>, AggregateError> {
    if outputs.fee_to_treasury_bps > 10_000
        || outputs.remainder >= 10_000
        || outputs.index_a >= 16
        || outputs.index_b >= 16
    {
        return Err(AggregateError::OutOfRange);
    }
    let product = u128::from(outputs.fee_sum) * u128::from(outputs.fee_to_treasury_bps);
    if product >= u128::from(Val::ORDER_U64) {
        return Err(AggregateError::OutOfRange);
    }
    Ok(vec![
        v(outputs.fee_sum)?,
        v(u32::from(outputs.fee_to_treasury_bps))?,
        v(outputs.treasury_fee)?,
        v(outputs.producer_fee)?,
        v(outputs.remainder)?,
        v(outputs.leaf_a)?,
        v(outputs.root_a)?,
        v(outputs.index_a)?,
        v(outputs.leaf_b)?,
        v(outputs.root_b)?,
        v(outputs.index_b)?,
        v(outputs.parent_digest[0])?,
        v(outputs.parent_digest[1])?,
        v(outputs.parent_digest[2])?,
        v(outputs.parent_digest[3])?,
    ])
}

fn v(value: u32) -> Result<Val, AggregateError> {
    if u64::from(value) >= Val::ORDER_U64 {
        Err(AggregateError::OutOfRange)
    } else {
        Ok(Val::from_u64(u64::from(value)))
    }
}

fn trace_for(
    claim: &AggregatedClaim,
    public: &[Val],
) -> Result<RowMajorMatrix<Val>, AggregateError> {
    let tree_a = padded(&claim.leaves_a)?;
    let tree_b = padded(&claim.leaves_b)?;
    let sib_a = siblings(&tree_a, claim.index_a as usize);
    let sib_b = siblings(&tree_b, claim.index_b as usize);
    let mut values = Val::zero_vec(TRACE_LEN * WIDTH);
    fill_path(&mut values, 0, public[P_LEAF_A], &sib_a, claim.index_a);
    fill_path(
        &mut values,
        PATH_SPAN,
        public[P_LEAF_B],
        &sib_b,
        claim.index_b,
    );
    Ok(RowMajorMatrix::new(values, WIDTH))
}

#[allow(clippy::needless_range_loop)]
fn fill_path(values: &mut [Val], base: usize, leaf: Val, siblings: &[Val], index: u32) {
    let mut cur = leaf;
    let mut acc = Val::ZERO;
    let mut place = Val::ONE;
    let mut steps_left = DEPTH;
    for row in 0..TRACE_LEN {
        let alive = if steps_left == 0 { Val::ZERO } else { Val::ONE };
        let bit_u = if row < DEPTH { (index >> row) & 1 } else { 0 };
        let bit = Val::from_u64(u64::from(bit_u));
        let sib = if row < DEPTH {
            siblings[row]
        } else {
            Val::ZERO
        };
        let left = if bit_u == 1 { sib } else { cur };
        let right = if bit_u == 1 { cur } else { sib };
        let (cols, parent) = round_columns(left, right);
        let inv = if steps_left == 0 {
            Val::ZERO
        } else {
            Val::from_u64(steps_left as u64).inverse()
        };
        let offset = row * WIDTH + base;
        let row_vals = [
            cur,
            sib,
            bit,
            left,
            right,
            place,
            acc,
            bit * place,
            Val::from_u64(steps_left as u64),
            alive,
            inv,
        ];
        for (col, value) in row_vals.iter().enumerate() {
            values[offset + col] = *value;
        }
        for (col, value) in cols.iter().enumerate() {
            values[offset + C_ROUNDS + col] = *value;
        }
        if steps_left > 0 {
            cur = parent;
            acc += bit * place;
            place *= Val::from_u64(2);
            steps_left -= 1;
        }
    }
}

fn round_columns(left: Val, right: Val) -> ([Val; ROUNDS * 4], Val) {
    let mut state = left + right + Val::from_u64(DOMAIN);
    let mut cols = [Val::ZERO; ROUNDS * 4];
    for (round, constant) in RC.iter().enumerate() {
        let x = state + Val::from_u64(*constant);
        let x2 = x * x;
        let x4 = x2 * x2;
        let x6 = x4 * x2;
        let y = x6 * x;
        cols[round * 4] = x2;
        cols[round * 4 + 1] = x4;
        cols[round * 4 + 2] = x6;
        cols[round * 4 + 3] = y;
        state = y;
    }
    (cols, state)
}

fn round_state(left: Val, right: Val) -> ([Val; ROUNDS * 4], Val) {
    round_columns(left, right)
}

fn padded(leaves: &[u32]) -> Result<Vec<Val>, AggregateError> {
    if leaves.is_empty() || leaves.len() > (1 << DEPTH) {
        return Err(AggregateError::OutOfRange);
    }
    let mut out = Vec::with_capacity(1 << DEPTH);
    for leaf in leaves {
        out.push(v32(*leaf)?);
    }
    out.resize(1 << DEPTH, Val::from_u64(PAD));
    Ok(out)
}

fn v32(value: u32) -> Result<Val, AggregateError> {
    v(value)
}

fn root_of(leaves: &[Val]) -> Val {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(babybear_merkle_compress(level[i], level[i + 1]));
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn siblings(leaves: &[Val], index: usize) -> Vec<Val> {
    let mut siblings = Vec::with_capacity(DEPTH);
    let mut level = leaves.to_vec();
    let mut idx = index;
    for _ in 0..DEPTH {
        siblings.push(if idx & 1 == 1 {
            level[idx - 1]
        } else {
            level[idx + 1]
        });
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(babybear_merkle_compress(level[i], level[i + 1]));
            i += 2;
        }
        level = next;
        idx >>= 1;
    }
    siblings
}

fn as_u32(value: Val) -> u32 {
    u32::try_from(value.as_canonical_u64()).unwrap_or(u32::MAX)
}

fn config() -> MyConfig {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters::new_testing(challenge_mmcs, 2);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    MyConfig::new(pcs, Challenger::new(perm))
}

struct AggregateAir;

impl BaseAir<Val> for AggregateAir {
    fn width(&self) -> usize {
        WIDTH
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB> Air<AB> for AggregateAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pis = builder.public_values();
        let fee = ex::<AB>(pis[P_FEE]);
        let bps = ex::<AB>(pis[P_BPS]);
        let treasury = ex::<AB>(pis[P_TREASURY]);
        let producer = ex::<AB>(pis[P_PRODUCER]);
        let rem = ex::<AB>(pis[P_REM]);
        let leaf_a = ex::<AB>(pis[P_LEAF_A]);
        let root_a = ex::<AB>(pis[P_ROOT_A]);
        let index_a = ex::<AB>(pis[P_INDEX_A]);
        let leaf_b = ex::<AB>(pis[P_LEAF_B]);
        let root_b = ex::<AB>(pis[P_ROOT_B]);
        let index_b = ex::<AB>(pis[P_INDEX_B]);

        {
            let mut first = builder.when_first_row();
            let ten_k = ex::<AB>(Val::from_u64(10_000));
            first.assert_eq(fee.clone() * bps, treasury.clone() * ten_k + rem);
            first.assert_eq(producer + treasury, fee);
            first.assert_eq(local[C_CUR], leaf_a);
            first.assert_eq(local[C_ACC], Val::ZERO);
            first.assert_eq(local[C_PLACE], Val::ONE);
            first.assert_eq(local[C_STEPS], Val::from_u64(DEPTH as u64));
            first.assert_eq(local[PATH_SPAN + C_CUR], leaf_b);
            first.assert_eq(local[PATH_SPAN + C_ACC], Val::ZERO);
            first.assert_eq(local[PATH_SPAN + C_PLACE], Val::ONE);
            first.assert_eq(local[PATH_SPAN + C_STEPS], Val::from_u64(DEPTH as u64));
        }
        {
            let mut last = builder.when_last_row();
            last.assert_eq(local[C_CUR], root_a);
            last.assert_eq(local[C_ACC], index_a);
            last.assert_eq(local[C_STEPS], Val::ZERO);
            last.assert_eq(local[PATH_SPAN + C_CUR], root_b);
            last.assert_eq(local[PATH_SPAN + C_ACC], index_b);
            last.assert_eq(local[PATH_SPAN + C_STEPS], Val::ZERO);
        }
        constrain_path(builder, local, next, 0);
        constrain_path(builder, local, next, PATH_SPAN);
    }
}

fn constrain_path<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    base: usize,
) {
    let bit = ex::<AB>(local[base + C_BIT]);
    let alive = ex::<AB>(local[base + C_ALIVE]);
    let one = ex::<AB>(Val::ONE);
    let cur = ex::<AB>(local[base + C_CUR]);
    let sib = ex::<AB>(local[base + C_SIB]);
    let steps = ex::<AB>(local[base + C_STEPS]);
    let place = ex::<AB>(local[base + C_PLACE]);
    builder.assert_eq(bit.clone() * (bit.clone() - one.clone()), Val::ZERO);
    builder.assert_eq(alive.clone() * (alive.clone() - one.clone()), Val::ZERO);
    builder.assert_eq((one.clone() - alive.clone()) * steps.clone(), Val::ZERO);
    builder.assert_eq(
        alive.clone() * (steps.clone() * ex::<AB>(local[base + C_INV]) - one.clone()),
        Val::ZERO,
    );
    builder.assert_eq(
        local[base + C_LEFT],
        (one.clone() - bit.clone()) * cur.clone() + bit.clone() * sib.clone(),
    );
    builder.assert_eq(
        local[base + C_RIGHT],
        (one.clone() - bit.clone()) * sib + bit.clone() * cur.clone(),
    );
    builder.assert_eq(local[base + C_CONTRIB], bit * place);

    let mut state = ex::<AB>(local[base + C_LEFT])
        + ex::<AB>(local[base + C_RIGHT])
        + ex::<AB>(Val::from_u64(DOMAIN));
    for (round, constant) in RC.iter().enumerate() {
        let x = state + ex::<AB>(Val::from_u64(*constant));
        let x2 = ex::<AB>(local[base + C_ROUNDS + round * 4]);
        let x4 = ex::<AB>(local[base + C_ROUNDS + round * 4 + 1]);
        let x6 = ex::<AB>(local[base + C_ROUNDS + round * 4 + 2]);
        let out = ex::<AB>(local[base + C_ROUNDS + round * 4 + 3]);
        builder.assert_eq(x2.clone(), x.clone() * x.clone());
        builder.assert_eq(x4.clone(), x2.clone() * x2.clone());
        builder.assert_eq(x6.clone(), x4 * x2);
        builder.assert_eq(out.clone(), x6 * x);
        state = out;
    }

    let mut trans = builder.when_transition();
    trans.assert_eq(
        next[base + C_CUR],
        cur.clone() + alive.clone() * (state - cur),
    );
    trans.assert_eq(
        next[base + C_ACC],
        ex::<AB>(local[base + C_ACC]) + alive.clone() * ex::<AB>(local[base + C_CONTRIB]),
    );
    trans.assert_eq(
        next[base + C_PLACE],
        ex::<AB>(local[base + C_PLACE]) * (one + alive.clone()),
    );
    trans.assert_eq(next[base + C_STEPS], steps - alive);
}

fn ex<AB: AirBuilder>(value: impl Into<AB::Expr>) -> AB::Expr {
    value.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim() -> AggregatedClaim {
        AggregatedClaim {
            fee_sum: 2_000,
            fee_to_treasury_bps: 2_500,
            treasury_fee: 500,
            producer_fee: 1_500,
            leaves_a: vec![11, 12, 13],
            index_a: 0,
            leaves_b: vec![21, 22, 23, 24],
            index_b: 3,
            parent_digest: [9, 8, 7, 6],
        }
    }

    fn outputs_of(claim: &AggregatedClaim) -> AggregatedOutputs {
        let product = u128::from(claim.fee_sum) * u128::from(claim.fee_to_treasury_bps);
        AggregatedOutputs {
            fee_sum: claim.fee_sum,
            fee_to_treasury_bps: claim.fee_to_treasury_bps,
            treasury_fee: claim.treasury_fee,
            producer_fee: claim.producer_fee,
            remainder: u32::try_from(product % 10_000).unwrap(),
            leaf_a: claim.leaves_a[claim.index_a as usize],
            root_a: babybear_merkle_root(&claim.leaves_a).unwrap(),
            index_a: claim.index_a,
            leaf_b: claim.leaves_b[claim.index_b as usize],
            root_b: babybear_merkle_root(&claim.leaves_b).unwrap(),
            index_b: claim.index_b,
            parent_digest: claim.parent_digest,
        }
    }

    #[test]
    fn b12_native_babybear_root_is_stable() {
        let root = babybear_merkle_root(&[11, 12, 13]).unwrap();
        assert_eq!(root, babybear_merkle_root(&[11, 12, 13]).unwrap());
        assert_ne!(root, babybear_merkle_root(&[11, 12, 14]).unwrap());
    }

    #[test]
    fn b12_plonky3_aggregates_split_and_two_openings() {
        let claim = claim();
        let proof = prove_aggregated(&claim).unwrap();
        verify_aggregated(&claim, &proof).unwrap();
        let mut tampered = claim.clone();
        tampered.producer_fee += 1;
        tampered.treasury_fee -= 1;
        assert!(verify_aggregated(&tampered, &proof).is_err());
        let mut bad_root = claim.clone();
        bad_root.leaves_a[0] ^= 1;
        assert!(verify_aggregated(&bad_root, &proof).is_err());
    }

    #[test]
    fn b39_light_verify_binds_parent_without_recomputing_split() {
        let claim = claim();
        let proof = prove_aggregated(&claim).unwrap();
        let outputs = outputs_of(&claim);
        verify_aggregated_outputs(&outputs, &proof).unwrap();

        let mut other_parent = outputs.clone();
        other_parent.parent_digest[0] ^= 1;
        assert_eq!(
            verify_aggregated_outputs(&other_parent, &proof),
            Err(AggregateError::ProofInvalid)
        );

        let mut other_split = outputs;
        other_split.producer_fee += 1;
        other_split.treasury_fee -= 1;
        assert_eq!(
            verify_aggregated_outputs(&other_split, &proof),
            Err(AggregateError::ProofInvalid)
        );
    }
}
