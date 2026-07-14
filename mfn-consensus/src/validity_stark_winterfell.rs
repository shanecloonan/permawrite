//! Winterfell STARK batch binding for **F5** phase 4b.1.
//!
//! Proves a deterministic field accumulator over `parent_checkpoint || block_wire`
//! chunks plus consensus-bound tx/coinbase/SPoRA batch metadata. Full nodes still
//! replay `apply_block` after STARK verification.

use crate::block::{decode_block, BlockDecodeError};
use crate::validity_stark_stub;
use mfn_crypto::dhash;
use mfn_crypto::domain::VALIDITY_STARK_WINTERFELL_BATCH;
use thiserror::Error;
use winter_utils::Deserializable;
use winterfell::FieldExtension;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    verify, AcceptableOptions, Air, AirContext, Assertion, AuxRandElements,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, PartitionOptions, Proof,
    ProofOptions, Prover, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

type Hasher = Blake3_256<BaseElement>;

/// Minimum trace length for the batch-binding STARK (including init row).
pub const MIN_BATCH_TRACE_LEN: usize = 8;
/// Maximum trace length accepted by the batch-binding prover.
pub const MAX_BATCH_TRACE_LEN: usize = 4096;

/// Batch metadata extracted from a decoded block body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchMeta {
    /// Number of transactions in the block body.
    pub tx_count: u32,
    /// Number of SPoRA storage proofs in the block body.
    pub spora_count: u32,
    /// `1` when the first transaction is a coinbase (no inputs), else `0`.
    pub coinbase_flag: u32,
}

/// Public STARK inputs for the batch-binding circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchPublicInputs {
    /// Field accumulator start derived from the circuit digest.
    pub start: BaseElement,
    /// Field accumulator end over the batch wire chunks.
    pub result: BaseElement,
    /// Extracted tx+coinbase+SPoRA batch metadata (consensus-bound public inputs).
    pub meta: BatchMeta,
}

impl ToElements<BaseElement> for BatchPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            self.start,
            self.result,
            BaseElement::new(self.meta.tx_count as u128),
            BaseElement::new(self.meta.spora_count as u128),
            BaseElement::new(self.meta.coinbase_flag as u128),
        ]
    }
}

/// STARK AIR for tx+coinbase+SPoRA batch binding (`acc' = acc * 127 + chunk`).
pub struct BatchBindingAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
    meta: BatchMeta,
}

impl Air for BatchBindingAir {
    type BaseField = BaseElement;
    type PublicInputs = BatchPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: BatchPublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(2)];
        let num_assertions = 5;
        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            start: pub_inputs.start,
            result: pub_inputs.result,
            meta: pub_inputs.meta,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let acc = frame.current()[0];
        let chunk = frame.current()[1];
        let expected = acc * E::from(127u32) + chunk;
        result[0] = frame.next()[0] - expected;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start),
            Assertion::single(0, last_step, self.result),
            Assertion::single(2, 0, BaseElement::new(self.meta.tx_count as u128)),
            Assertion::single(2, 1, BaseElement::new(self.meta.spora_count as u128)),
            Assertion::single(2, 2, BaseElement::new(self.meta.coinbase_flag as u128)),
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

struct BatchBindingProver {
    options: ProofOptions,
    meta: BatchMeta,
}

impl BatchBindingProver {
    fn new(options: ProofOptions, meta: BatchMeta) -> Self {
        Self { options, meta }
    }
}

impl Prover for BatchBindingProver {
    type BaseField = BaseElement;
    type Air = BatchBindingAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = MerkleTree<Hasher>;
    type RandomCoin = DefaultRandomCoin<Hasher>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Hasher, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, BatchBindingAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> BatchPublicInputs {
        let last_step = trace.length() - 1;
        BatchPublicInputs {
            start: trace.get(0, 0),
            result: trace.get(0, last_step),
            meta: self.meta,
        }
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a BatchBindingAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

/// Errors from Winterfell batch STARK prove/verify.
#[derive(Debug, Error)]
pub enum WinterfellBatchError {
    /// Parent or block wire failed decode.
    #[error("batch meta decode: {0}")]
    BatchMeta(#[from] BlockDecodeError),
    /// Trace length out of supported bounds.
    #[error("batch trace length {len} outside [{min}, {max}]")]
    TraceLength {
        /// Computed trace length.
        len: usize,
        /// Minimum supported length.
        min: usize,
        /// Maximum supported length.
        max: usize,
    },
    /// STARK proof bytes could not be decoded.
    #[error("stark proof decode failed")]
    ProofDecode,
    /// STARK verification failed.
    #[error("stark proof invalid")]
    ProofInvalid,
    /// Circuit digest does not match the batch v1 id.
    #[error("batch circuit digest mismatch")]
    CircuitDigestMismatch,
    /// Prover failed to generate a proof.
    #[error("stark prove failed")]
    ProveFailed,
}

/// Extract tx / coinbase / SPoRA counts from an encoded block body.
pub fn batch_meta_from_block_wire(block_wire: &[u8]) -> Result<BatchMeta, BlockDecodeError> {
    let block = decode_block(block_wire)?;
    let tx_count = block.txs.len() as u32;
    let spora_count = block.storage_proofs.len() as u32;
    let coinbase_flag = block
        .txs
        .first()
        .map(|tx| tx.inputs.is_empty())
        .unwrap_or(false) as u32;
    Ok(BatchMeta {
        tx_count,
        spora_count,
        coinbase_flag,
    })
}

fn num_acc_steps(parent_checkpoint: &[u8], block_wire: &[u8]) -> usize {
    let payload_len = parent_checkpoint.len().saturating_add(block_wire.len());
    payload_len.div_ceil(32)
}

fn batch_trace_len(parent_checkpoint: &[u8], block_wire: &[u8]) -> usize {
    let acc_rows = num_acc_steps(parent_checkpoint, block_wire)
        .saturating_add(1)
        .max(3);
    acc_rows
        .next_power_of_two()
        .clamp(MIN_BATCH_TRACE_LEN, MAX_BATCH_TRACE_LEN)
}

fn hold_chunk(acc: BaseElement) -> BaseElement {
    acc - acc * BaseElement::new(127)
}

fn field_from_digest_byte(digest: &[u8; 32], idx: usize) -> BaseElement {
    let off = idx % 24;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest[off..off + 8]);
    BaseElement::new(u64::from_le_bytes(buf) as u128)
}

fn start_field(circuit_digest: &[u8; 32]) -> BaseElement {
    field_from_digest_byte(circuit_digest, 8)
}

fn chunk_element(parent_checkpoint: &[u8], block_wire: &[u8], step: usize) -> BaseElement {
    let mut buf = [0u8; 32];
    let payload_len = parent_checkpoint.len().saturating_add(block_wire.len());
    let start = step.saturating_mul(32);
    if start >= payload_len {
        return BaseElement::ZERO;
    }
    let end = (start + 32).min(payload_len);
    let mut pos = 0usize;
    while pos < 32 && start + pos < payload_len {
        let parent_len = parent_checkpoint.len();
        let abs = start + pos;
        buf[pos] = if abs < parent_len {
            parent_checkpoint[abs]
        } else {
            block_wire[abs - parent_len]
        };
        pos += 1;
    }
    let tag = dhash(
        VALIDITY_STARK_WINTERFELL_BATCH,
        &[&(end - start).to_le_bytes()],
    );
    for i in 0..8 {
        buf[i] ^= tag[i];
    }
    BaseElement::new(u64::from_le_bytes(buf[0..8].try_into().expect("8 bytes")) as u128)
}

fn compute_binding_result(
    parent_checkpoint: &[u8],
    block_wire: &[u8],
    start: BaseElement,
) -> BaseElement {
    let steps = num_acc_steps(parent_checkpoint, block_wire);
    let mut acc = start;
    for step in 0..steps {
        acc = acc * BaseElement::new(127) + chunk_element(parent_checkpoint, block_wire, step);
    }
    acc
}

fn build_batch_binding_trace(
    parent_checkpoint: &[u8],
    block_wire: &[u8],
    start: BaseElement,
    result: BaseElement,
    meta: BatchMeta,
) -> TraceTable<BaseElement> {
    let n = batch_trace_len(parent_checkpoint, block_wire);
    let acc_rows = num_acc_steps(parent_checkpoint, block_wire)
        .saturating_add(1)
        .max(1);
    let init_chunk = if num_acc_steps(parent_checkpoint, block_wire) == 0 {
        hold_chunk(start)
    } else {
        chunk_element(parent_checkpoint, block_wire, 0)
    };
    let mut trace = TraceTable::new(3, n);
    trace.fill(
        |state| {
            state[0] = start;
            state[1] = init_chunk;
            state[2] = BaseElement::new(meta.tx_count as u128);
        },
        |step, state| {
            if step + 1 >= n {
                return;
            }
            state[0] = state[0] * BaseElement::new(127) + state[1];
            if step + 1 < acc_rows.saturating_sub(1) {
                state[1] = chunk_element(parent_checkpoint, block_wire, step + 1);
            } else {
                state[1] = hold_chunk(result);
            }
            state[2] = match step + 1 {
                1 => BaseElement::new(meta.spora_count as u128),
                2 => BaseElement::new(meta.coinbase_flag as u128),
                _ => BaseElement::ZERO,
            };
        },
    );
    trace
}

fn proof_options_fast() -> ProofOptions {
    ProofOptions::new(32, 8, 0, FieldExtension::None, 8, 31)
}

/// Prove batch binding for `parent_checkpoint` + `block_wire` using Winterfell.
pub fn prove_batch_binding_stark(
    parent_checkpoint: &[u8],
    block_wire: &[u8],
    circuit_digest: &[u8; 32],
) -> Result<Vec<u8>, WinterfellBatchError> {
    if circuit_digest != &validity_stark_stub::validity_stark_batch_v1_circuit_digest() {
        return Err(WinterfellBatchError::CircuitDigestMismatch);
    }
    let meta = batch_meta_from_block_wire(block_wire)?;
    let len = batch_trace_len(parent_checkpoint, block_wire);
    if !(MIN_BATCH_TRACE_LEN..=MAX_BATCH_TRACE_LEN).contains(&len) {
        return Err(WinterfellBatchError::TraceLength {
            len,
            min: MIN_BATCH_TRACE_LEN,
            max: MAX_BATCH_TRACE_LEN,
        });
    }
    let start = start_field(circuit_digest);
    let result = compute_binding_result(parent_checkpoint, block_wire, start);
    let trace = build_batch_binding_trace(parent_checkpoint, block_wire, start, result, meta);
    let prover = BatchBindingProver::new(proof_options_fast(), meta);
    let proof = prover
        .prove(trace)
        .map_err(|_| WinterfellBatchError::ProveFailed)?;
    Ok(proof.to_bytes())
}

/// Verify Winterfell batch-binding STARK proof bytes.
pub fn verify_batch_binding_stark(
    parent_checkpoint: &[u8],
    block_wire: &[u8],
    circuit_digest: &[u8; 32],
    proof_bytes: &[u8],
) -> Result<(), WinterfellBatchError> {
    if circuit_digest != &validity_stark_stub::validity_stark_batch_v1_circuit_digest() {
        return Err(WinterfellBatchError::CircuitDigestMismatch);
    }
    let meta = batch_meta_from_block_wire(block_wire)?;
    let start = start_field(circuit_digest);
    let result = compute_binding_result(parent_checkpoint, block_wire, start);
    let pub_inputs = BatchPublicInputs {
        start,
        result,
        meta,
    };
    let proof =
        Proof::read_from_bytes(proof_bytes).map_err(|_| WinterfellBatchError::ProofDecode)?;
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
    verify::<BatchBindingAir, Hasher, DefaultRandomCoin<Hasher>, MerkleTree<Hasher>>(
        proof, pub_inputs, &min_opts,
    )
    .map_err(|_| WinterfellBatchError::ProofInvalid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{
        apply_genesis, build_genesis, build_unsealed_header, seal_block, GenesisConfig,
        TEST_CONSENSUS_PARAMS,
    };
    use crate::emission::DEFAULT_EMISSION_PARAMS;
    use mfn_storage::DEFAULT_ENDOWMENT_PARAMS;

    fn legacy_genesis() -> (crate::ChainState, [u8; 32]) {
        let cfg = GenesisConfig {
            timestamp: 0,
            initial_outputs: Vec::new(),
            initial_storage: Vec::new(),
            initial_storage_operators: Vec::new(),
            validators: Vec::new(),
            params: TEST_CONSENSUS_PARAMS,
            emission_params: DEFAULT_EMISSION_PARAMS,
            endowment_params: DEFAULT_ENDOWMENT_PARAMS,
            bonding_params: None,
            header_version: 1,
        };
        let g = build_genesis(&cfg);
        let genesis_id = crate::block_id(&g.header);
        let state = apply_genesis(&g, &cfg).expect("genesis");
        (state, genesis_id)
    }

    #[test]
    fn winterfell_batch_proof_roundtrip() {
        let (parent, genesis_id) = legacy_genesis();
        let cp = crate::ChainCheckpoint {
            genesis_id,
            state: parent.clone(),
        };
        let header = build_unsealed_header(&parent, &[], &[], &[], &[], 1, 100);
        let block = seal_block(header, vec![], vec![], vec![], vec![], vec![]);
        let parent_checkpoint = crate::encode_chain_checkpoint(&cp);
        let block_wire = crate::encode_block(&block);
        let circuit = validity_stark_stub::validity_stark_batch_v1_circuit_digest();
        let proof_bytes =
            prove_batch_binding_stark(&parent_checkpoint, &block_wire, &circuit).expect("prove");
        verify_batch_binding_stark(&parent_checkpoint, &block_wire, &circuit, &proof_bytes)
            .expect("verify");
    }
}
