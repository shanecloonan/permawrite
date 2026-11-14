//! F5 phase **4a** field-Merkle opening (B-317). Not consensus.
//!
//! Proves a depth-4 path under [`field_merkle_compress`], an 8-round MiMC-5
//! permutation on Winterfell's `f128`. This is not [`mfn_crypto::merkle`]:
//! consensus nodes still compress with SHA-512 `dhash`. A SHA-512 AIR is not
//! the cheap leaf. Callers pad to 16 leaves with [`FIELD_MERKLE_PAD`].
//!
//! Nothing here is a header field, a gossip message, or a genesis change.

use thiserror::Error;
use winter_utils::Deserializable;
use winterfell::math::{fields::f128::BaseElement, FieldElement, ToElements};
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    verify, AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions,
    Proof, ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

type Hasher = Blake3_256<BaseElement>;

/// Path length of the field-Merkle leaf. Capacity is `1 << DEPTH` leaves.
pub const FIELD_MERKLE_DEPTH: usize = 4;
/// MiMC-5 rounds inside one parent hash.
pub const FIELD_MERKLE_ROUNDS: usize = 8;
/// Leaf used to pad a short list up to [`FIELD_MERKLE_DEPTH`] capacity.
pub const FIELD_MERKLE_PAD: u128 = 2;
const DOMAIN: u128 = 0x004d_464e;
const RC: [u128; FIELD_MERKLE_ROUNDS] = [3, 5, 7, 11, 13, 17, 19, 23];

const TRACE_LEN: usize = 8;
const CHECK_ROW: u128 = 4;
const WIDTH: usize = 42;
const ROUND0: usize = 18;

const C_LEAF: usize = 0;
const C_ROOT: usize = 1;
const C_INDEX: usize = 2;
const C_CUR: usize = 3;
const C_SIB: usize = 4;
const C_BIT: usize = 5;
const C_LEFT: usize = 6;
const C_RIGHT: usize = 7;
const C_PLACE: usize = 8;
const C_ACC: usize = 9;
const C_CONTRIB: usize = 10;
const C_STEP: usize = 11;
const C_STEPS: usize = 12;
const C_ALIVE: usize = 13;
const C_AINV: usize = 14;
const C_AOK: usize = 15;
const C_SLACK_ROOT: usize = 16;
const C_SLACK_INDEX: usize = 17;

const HELD: [usize; 3] = [C_LEAF, C_ROOT, C_INDEX];

fn x2_col(round: usize) -> usize {
    ROUND0 + round * 3
}
fn x4_col(round: usize) -> usize {
    ROUND0 + round * 3 + 1
}
fn out_col(round: usize) -> usize {
    ROUND0 + round * 3 + 2
}

/// Failures of the field-Merkle leaf.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FieldMerkleError {
    /// No leaves were supplied.
    #[error("field merkle requires at least one leaf")]
    Empty,
    /// More leaves than the fixed depth can hold.
    #[error("field merkle leaf list exceeds the fixed depth")]
    TooMany,
    /// Opening index is outside the padded tree.
    #[error("field merkle index is outside the fixed depth")]
    Index,
    /// Trace does not match the native compress function.
    #[error("field merkle trace is inconsistent")]
    TraceInconsistent,
    /// Winterfell prover failed.
    #[error("stark prove failed")]
    ProveFailed,
    /// Proof bytes were not a Winterfell proof.
    #[error("stark proof decode failed")]
    ProofDecode,
    /// Winterfell rejected the proof.
    #[error("stark proof invalid")]
    ProofInvalid,
}

/// Public opening: padded-tree leaf, root, and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMerkleClaim {
    /// Leaf value in the field (after padding).
    pub leaf: BaseElement,
    /// Root of the depth-[`FIELD_MERKLE_DEPTH`] field tree.
    pub root: BaseElement,
    /// Index in the padded tree. Must be `< 1 << FIELD_MERKLE_DEPTH`.
    pub index: u32,
}

/// Parent hash. Eight cubeless fifth-power rounds over `f128`.
pub fn field_merkle_compress(left: BaseElement, right: BaseElement) -> BaseElement {
    let mut state = left + right + fe(DOMAIN);
    for constant in RC {
        let x = state + fe(constant);
        let x2 = x.square();
        let x4 = x2.square();
        state = x4 * x;
    }
    state
}

/// Pad with [`FIELD_MERKLE_PAD`] and return the field-Merkle root.
pub fn field_merkle_root(leaves: &[BaseElement]) -> Result<BaseElement, FieldMerkleError> {
    Ok(root_of(&padded(leaves)?))
}

/// Honest opening claim for `index` in the padded tree.
pub fn field_merkle_claim(
    leaves: &[BaseElement],
    index: u32,
) -> Result<FieldMerkleClaim, FieldMerkleError> {
    let tree = padded(leaves)?;
    let index = checked_index(index)?;
    Ok(FieldMerkleClaim {
        leaf: tree[index],
        root: root_of(&tree),
        index: index as u32,
    })
}

/// Prove an opening. Siblings stay inside the proof.
pub fn prove_field_merkle(
    leaves: &[BaseElement],
    index: u32,
) -> Result<(FieldMerkleClaim, Vec<u8>), FieldMerkleError> {
    let tree = padded(leaves)?;
    let index = checked_index(index)?;
    let claim = FieldMerkleClaim {
        leaf: tree[index],
        root: root_of(&tree),
        index: index as u32,
    };
    let siblings = siblings_for(&tree, index);
    let proof = prove_opening(&claim, &siblings)?;
    Ok((claim, proof))
}

/// Verify a field-Merkle STARK. Does not re-hash the path in the clear.
pub fn verify_field_merkle(
    claim: &FieldMerkleClaim,
    proof_bytes: &[u8],
) -> Result<(), FieldMerkleError> {
    if claim.index >= (1u32 << FIELD_MERKLE_DEPTH) {
        return Err(FieldMerkleError::Index);
    }
    let proof = Proof::read_from_bytes(proof_bytes).map_err(|_| FieldMerkleError::ProofDecode)?;
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
    verify::<MerkleAir, Hasher, DefaultRandomCoin<Hasher>, MerkleTree<Hasher>>(
        proof,
        MerklePublic::from_claim(claim),
        &min_opts,
    )
    .map_err(|_| FieldMerkleError::ProofInvalid)
}

fn fe(value: u128) -> BaseElement {
    BaseElement::new(value)
}

fn padded(leaves: &[BaseElement]) -> Result<Vec<BaseElement>, FieldMerkleError> {
    if leaves.is_empty() {
        return Err(FieldMerkleError::Empty);
    }
    let cap = 1usize << FIELD_MERKLE_DEPTH;
    if leaves.len() > cap {
        return Err(FieldMerkleError::TooMany);
    }
    let mut out = leaves.to_vec();
    out.resize(cap, fe(FIELD_MERKLE_PAD));
    Ok(out)
}

fn checked_index(index: u32) -> Result<usize, FieldMerkleError> {
    let cap = 1u32 << FIELD_MERKLE_DEPTH;
    if index >= cap {
        Err(FieldMerkleError::Index)
    } else {
        Ok(index as usize)
    }
}

fn root_of(leaves: &[BaseElement]) -> BaseElement {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(field_merkle_compress(left, right));
            i += 2;
        }
        level = next;
    }
    level[0]
}

fn siblings_for(leaves: &[BaseElement], index: usize) -> Vec<BaseElement> {
    let mut siblings = Vec::with_capacity(FIELD_MERKLE_DEPTH);
    let mut level = leaves.to_vec();
    let mut idx = index;
    for _ in 0..FIELD_MERKLE_DEPTH {
        let sib = if idx & 1 == 1 {
            level[idx - 1]
        } else {
            level[idx + 1]
        };
        siblings.push(sib);
        let mut next = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            next.push(field_merkle_compress(level[i], level[i + 1]));
            i += 2;
        }
        level = next;
        idx >>= 1;
    }
    siblings
}

fn ratio(numer: BaseElement, denom: BaseElement) -> BaseElement {
    if denom == BaseElement::ZERO {
        BaseElement::ZERO
    } else {
        numer * denom.inv()
    }
}

fn prove_opening(
    claim: &FieldMerkleClaim,
    siblings: &[BaseElement],
) -> Result<Vec<u8>, FieldMerkleError> {
    if siblings.len() != FIELD_MERKLE_DEPTH {
        return Err(FieldMerkleError::TraceInconsistent);
    }
    let rows = merkle_rows(claim, siblings)?;
    let prover = MerkleProver {
        options: ProofOptions::new(32, 8, 0, FieldExtension::None, 8, 31),
    };
    let proof = prover
        .prove(rows_to_trace(&rows))
        .map_err(|_| FieldMerkleError::ProveFailed)?;
    Ok(proof.to_bytes())
}

fn rows_to_trace(rows: &[Vec<BaseElement>]) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(WIDTH, rows.len());
    trace.fill(
        |state| state.copy_from_slice(&rows[0]),
        |step, state| state.copy_from_slice(&rows[step + 1]),
    );
    trace
}

#[allow(clippy::too_many_lines, clippy::needless_range_loop)]
fn merkle_rows(
    claim: &FieldMerkleClaim,
    siblings: &[BaseElement],
) -> Result<Vec<Vec<BaseElement>>, FieldMerkleError> {
    let check = fe(CHECK_ROW);
    let mut cur = claim.leaf;
    let mut acc = BaseElement::ZERO;
    let mut place = BaseElement::ONE;
    let mut steps = fe(FIELD_MERKLE_DEPTH as u128);
    let mut rows = Vec::with_capacity(TRACE_LEN);
    for row in 0..TRACE_LEN {
        let alive = if steps == BaseElement::ZERO {
            BaseElement::ZERO
        } else {
            BaseElement::ONE
        };
        let bit = if row < FIELD_MERKLE_DEPTH {
            fe(((claim.index >> row) & 1) as u128)
        } else {
            BaseElement::ZERO
        };
        let sib = if row < FIELD_MERKLE_DEPTH {
            siblings[row]
        } else {
            BaseElement::ZERO
        };
        let left = (BaseElement::ONE - bit) * cur + bit * sib;
        let right = (BaseElement::ONE - bit) * sib + bit * cur;
        let mut state = left + right + fe(DOMAIN);
        let mut round_cells = [BaseElement::ZERO; FIELD_MERKLE_ROUNDS * 3];
        for round in 0..FIELD_MERKLE_ROUNDS {
            let x = state + fe(RC[round]);
            let x2 = x.square();
            let x4 = x2.square();
            let y = x4 * x;
            round_cells[round * 3] = x2;
            round_cells[round * 3 + 1] = x4;
            round_cells[round * 3 + 2] = y;
            state = y;
        }
        if alive == BaseElement::ONE && state != field_merkle_compress(left, right) {
            return Err(FieldMerkleError::TraceInconsistent);
        }
        let step = fe(row as u128);
        let denom = step - check;
        let mut cells = vec![BaseElement::ZERO; WIDTH];
        cells[C_LEAF] = claim.leaf;
        cells[C_ROOT] = claim.root;
        cells[C_INDEX] = fe(u128::from(claim.index));
        cells[C_CUR] = cur;
        cells[C_SIB] = sib;
        cells[C_BIT] = bit;
        cells[C_LEFT] = left;
        cells[C_RIGHT] = right;
        cells[C_PLACE] = place;
        cells[C_ACC] = acc;
        cells[C_CONTRIB] = bit * place;
        cells[C_STEP] = step;
        cells[C_STEPS] = steps;
        cells[C_ALIVE] = alive;
        cells[C_AINV] = if steps == BaseElement::ZERO {
            BaseElement::ZERO
        } else {
            steps.inv()
        };
        cells[C_AOK] = alive;
        cells[C_SLACK_ROOT] = ratio(cur - claim.root, denom);
        cells[C_SLACK_INDEX] = ratio(acc - fe(u128::from(claim.index)), denom);
        for (i, value) in round_cells.iter().enumerate() {
            cells[ROUND0 + i] = *value;
        }
        if row == CHECK_ROW as usize
            && (cur != claim.root
                || acc != fe(u128::from(claim.index))
                || steps != BaseElement::ZERO)
        {
            return Err(FieldMerkleError::TraceInconsistent);
        }
        rows.push(cells);
        if row + 1 == TRACE_LEN {
            break;
        }
        if alive == BaseElement::ONE {
            cur = state;
            acc += bit * place;
            place *= fe(2);
            steps -= BaseElement::ONE;
        }
    }
    Ok(rows)
}

#[derive(Debug, Clone, Copy)]
struct MerklePublic {
    leaf: BaseElement,
    root: BaseElement,
    index: BaseElement,
}

impl MerklePublic {
    fn from_claim(claim: &FieldMerkleClaim) -> Self {
        Self {
            leaf: claim.leaf,
            root: claim.root,
            index: fe(u128::from(claim.index)),
        }
    }
}

impl ToElements<BaseElement> for MerklePublic {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.leaf, self.root, self.index]
    }
}

struct MerkleAir {
    context: AirContext<BaseElement>,
    public: MerklePublic,
}

impl Air for MerkleAir {
    type BaseField = BaseElement;
    type PublicInputs = MerklePublic;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, public: MerklePublic, options: ProofOptions) -> Self {
        Self {
            context: AirContext::new(
                trace_info,
                vec![TransitionConstraintDegree::new(2); MERKLE_CONSTRAINTS],
                MERKLE_ASSERTIONS,
                options,
            ),
            public,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();
        let one = E::ONE;
        let gate = cur[C_STEP] - E::from(CHECK_ROW as u32);
        let mut vals = Vec::with_capacity(MERKLE_CONSTRAINTS);
        for &col in &HELD {
            vals.push(nxt[col] - cur[col]);
        }
        vals.push(nxt[C_STEP] - cur[C_STEP] - one);
        vals.push(cur[C_STEP] * (nxt[C_STEP] - cur[C_STEP] - one));
        vals.push(cur[C_BIT] * (cur[C_BIT] - one));
        vals.push(cur[C_LEFT] - ((one - cur[C_BIT]) * cur[C_CUR] + cur[C_BIT] * cur[C_SIB]));
        vals.push(cur[C_RIGHT] - ((one - cur[C_BIT]) * cur[C_SIB] + cur[C_BIT] * cur[C_CUR]));
        vals.push(cur[C_CONTRIB] - cur[C_BIT] * cur[C_PLACE]);
        vals.push(cur[C_ALIVE] * (cur[C_ALIVE] - one));
        vals.push((one - cur[C_ALIVE]) * cur[C_STEPS]);
        vals.push(cur[C_AOK] - cur[C_STEPS] * cur[C_AINV]);
        vals.push(cur[C_ALIVE] * (cur[C_AOK] - one));
        vals.push(nxt[C_PLACE] - cur[C_PLACE] * (one + cur[C_ALIVE]));
        vals.push(nxt[C_ACC] - cur[C_ACC] - cur[C_ALIVE] * cur[C_CONTRIB]);
        vals.push(nxt[C_STEPS] - (cur[C_STEPS] - cur[C_ALIVE]));
        let mut state = cur[C_LEFT] + cur[C_RIGHT] + E::from(DOMAIN as u32);
        for round in 0..FIELD_MERKLE_ROUNDS {
            let x = state + E::from(RC[round] as u32);
            let x2 = cur[x2_col(round)];
            let x4 = cur[x4_col(round)];
            let out = cur[out_col(round)];
            vals.push(x2 - x * x);
            vals.push(x4 - x2 * x2);
            vals.push(out - x4 * x);
            state = out;
        }
        vals.push(nxt[C_CUR] - (cur[C_CUR] + cur[C_ALIVE] * (state - cur[C_CUR])));
        vals.push((cur[C_CUR] - cur[C_ROOT]) - gate * cur[C_SLACK_ROOT]);
        vals.push((cur[C_ACC] - cur[C_INDEX]) - gate * cur[C_SLACK_INDEX]);
        assert_eq!(vals.len(), result.len(), "merkle constraint count");
        result.copy_from_slice(&vals);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let p = &self.public;
        vec![
            Assertion::single(C_LEAF, 0, p.leaf),
            Assertion::single(C_ROOT, 0, p.root),
            Assertion::single(C_INDEX, 0, p.index),
            Assertion::single(C_CUR, 0, p.leaf),
            Assertion::single(C_PLACE, 0, BaseElement::ONE),
            Assertion::single(C_ACC, 0, BaseElement::ZERO),
            Assertion::single(C_STEP, 0, BaseElement::ZERO),
            Assertion::single(C_STEPS, 0, BaseElement::new(FIELD_MERKLE_DEPTH as u128)),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

const MERKLE_ASSERTIONS: usize = 8;
const MERKLE_CONSTRAINTS: usize = 3 + 2 + 4 + 4 + 3 + 1 + 2 + FIELD_MERKLE_ROUNDS * 3;

struct MerkleProver {
    options: ProofOptions,
}

impl Prover for MerkleProver {
    type BaseField = BaseElement;
    type Air = MerkleAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = MerkleTree<Hasher>;
    type RandomCoin = DefaultRandomCoin<Hasher>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Hasher, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, MerkleAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> MerklePublic {
        MerklePublic {
            leaf: trace.get(C_LEAF, 0),
            root: trace.get(C_ROOT, 0),
            index: trace.get(C_INDEX, 0),
        }
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a MerkleAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u128) -> BaseElement {
        BaseElement::new(n + 10)
    }

    #[test]
    fn b317_native_root_matches_manual_path() {
        let leaves: Vec<_> = (1..=5).map(leaf).collect();
        let root = field_merkle_root(&leaves).unwrap();
        let padded = padded(&leaves).unwrap();
        let mut cur = padded[3];
        let mut idx = 3usize;
        let mut level = padded.clone();
        for _ in 0..FIELD_MERKLE_DEPTH {
            let sib = if idx & 1 == 1 {
                level[idx - 1]
            } else {
                level[idx + 1]
            };
            cur = if idx & 1 == 1 {
                field_merkle_compress(sib, cur)
            } else {
                field_merkle_compress(cur, sib)
            };
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                next.push(field_merkle_compress(level[i], level[i + 1]));
                i += 2;
            }
            level = next;
            idx >>= 1;
        }
        assert_eq!(cur, root);
        assert!(field_merkle_root(&[]).is_err());
        assert!(field_merkle_claim(&leaves, 16).is_err());
    }

    #[test]
    fn b317_field_merkle_stark_opens_and_rejects_tamper() {
        let leaves: Vec<_> = (1..=5).map(leaf).collect();
        for index in [0u32, 4] {
            let (claim, proof) = prove_field_merkle(&leaves, index).unwrap();
            assert_eq!(claim.leaf, leaf(u128::from(index) + 1));
            verify_field_merkle(&claim, &proof).unwrap();
            let mut bad = claim;
            bad.root += BaseElement::ONE;
            assert!(verify_field_merkle(&bad, &proof).is_err());
            let mut bad_index = claim;
            bad_index.index ^= 1;
            assert!(verify_field_merkle(&bad_index, &proof).is_err());
        }
    }
}
