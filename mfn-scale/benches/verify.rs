#![allow(missing_docs)]

//! Criterion timings for the pinned verification workload.
//!
//! Run: `cargo bench -p mfn-scale --bench verify`
//!
//! The unit test pins sizes and the header-link digest. These numbers are
//! the wall-clock companion, recorded in `docs/SCALE_I1_VERIFY_BASELINE.md`.

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use mfn_scale::workload::prepare_verify_workload;
use mfn_scale::{
    header_link_digest, proofs_from_workload, verify_batch, BASELINE_HEADER_LINK_BLOCKS,
};

fn verify_benches(c: &mut Criterion) {
    let prepared = prepare_verify_workload().expect("workload");
    let mut group = c.benchmark_group("mfn_scale_verify");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(2));
    group.bench_function("merkle_32_of_1024", |b| {
        b.iter(|| black_box(prepared.verify_merkle()));
    });
    group.bench_function("clsag_ring16", |b| {
        b.iter(|| black_box(prepared.verify_clsag()));
    });
    group.bench_function("range_borromean_16", |b| {
        b.iter(|| black_box(prepared.verify_range()));
    });
    group.bench_function("bulletproof_16", |b| {
        b.iter(|| black_box(prepared.verify_bulletproof()));
    });
    group.bench_function("header_link_4096", |b| {
        b.iter(|| black_box(header_link_digest(BASELINE_HEADER_LINK_BLOCKS)));
    });
    group.bench_function("full_pass", |b| {
        b.iter(|| black_box(prepared.verify()));
    });
    let batch = proofs_from_workload(&prepared, 2);
    group.bench_function("batch_parallel_4", |b| {
        b.iter(|| black_box(verify_batch(&batch, 4)));
    });
    group.bench_function("batch_sequential", |b| {
        b.iter(|| black_box(verify_batch(&batch, 1)));
    });
    group.finish();
}

criterion_group!(benches, verify_benches);
criterion_main!(benches);
