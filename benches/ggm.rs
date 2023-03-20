use std::ops::Range;

use cprf::ggm::{GgmRCPrfConstrainedKey, GgmRCPrfMasterKey};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use generic_array::GenericArray;
use rand::{rngs::OsRng, RngCore};

fn get_ck(range: Range<u64>) -> GgmRCPrfConstrainedKey {
    let mut key = GenericArray::from([0u8; 16]);
    OsRng.fill_bytes(&mut key);
    let mk = GgmRCPrfMasterKey::new(key);

    mk.constrained(range)
}

fn bench_ggm_evaluate_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("GGM ck evaluate vs evaluate_all");
    for i in (1000..=20000).step_by(1000) {
        group.bench_function(BenchmarkId::new("evalate for each", i), |b| {
            b.iter_batched(
                || get_ck(2000..2000 + i + 1),
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
                || get_ck(2000..2000 + i),
                |ck| ck.evaluate_all().for_each(|_| ()),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(benches, bench_ggm_evaluate_all);
criterion_main!(benches);
