use std::time::Duration;

use cprf::ggm::{Ggm64ConstrainedKey, Ggm64MasterKey};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use pprof::criterion::{Output, PProfProfiler};
use rand::{rngs::OsRng, RngCore};

fn get_ck(a: u64, b: u64) -> Ggm64ConstrainedKey {
    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    let mk = Ggm64MasterKey::new_from_slice(&key);

    mk.constrain(a, b)
}

fn bench_ggm_evaluate_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("GGM ck evaluate vs evaluate_all");
    for i in [1000, 2500, 5000, 7500, 10000].iter() {
        group.bench_function(BenchmarkId::new("evalate for each", i), |b| {
            b.iter_batched(
                || get_ck(2001, 2000 + i),
                |ck| {
                    (ck.get_range().0..=ck.get_range().1).for_each(|x| {
                        ck.evaluate(black_box(x));
                    })
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(BenchmarkId::new("evalate_all", i), |b| {
            b.iter_batched(
                || get_ck(2001, 2000 + i),
                |ck| ck.evaluate_all().for_each(|_| ()),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(200).measurement_time(Duration::new(20, 0)).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_ggm_evaluate_all
);
criterion_main!(benches);
