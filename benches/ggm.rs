use cprf::ggm::GgmRCPrfMasterKey;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, black_box};
use generic_array::GenericArray;

fn bench_ggm_evaluate_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("GGM evaluate_all");
    for i in [10u64, 100u64, 1000u64, 5000u64].iter() {
        let key = GenericArray::from([0u8; 16]);
        let mk = GgmRCPrfMasterKey::new(key);
        let ck = mk.constrained(2000..2000+i+1);
        group.bench_function(BenchmarkId::new("evalate for each", i), |b| b.iter(|| (ck.get_range().0..=ck.get_range().1).for_each(|x| {ck.evaluate(black_box(x));})));
        group.bench_function(BenchmarkId::new("evalate_all", i), |b| b.iter(|| ck.evaluate_all().for_each(|_| ())));
    }
}

criterion_group!(benches, bench_ggm_evaluate_all);
criterion_main!(benches);