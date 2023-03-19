use cprf::ggm::GgmRCPrfMasterKey;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, black_box};
use generic_array::GenericArray;

fn fibonacci_slow(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci_slow(n-1) + fibonacci_slow(n-2),
    }
}

fn fibonacci_fast(n: u64) -> u64 {
    let mut a = 0;
    let mut b = 1;

    match n {
        0 => b,
        _ => {
            for _ in 0..n {
                let c = a + b;
                a = b;
                b = c;
            }
            b
        }
    }
}


fn bench_fibs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fibonacci");
    for i in [20u64, 21u64].iter() {
        group.bench_with_input(BenchmarkId::new("Recursive", i), i, 
            |b, i| b.iter(|| fibonacci_slow(*i)));
        group.bench_with_input(BenchmarkId::new("Iterative", i), i, 
            |b, i| b.iter(|| fibonacci_fast(*i)));
    }
    group.finish();
}

fn bench_ggm_evaluate_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("GGM evaluate_all");
    for i in [10u64, 100u64, 1000u64].iter() {
        let key = GenericArray::from([0u8; 16]);
        let mk = GgmRCPrfMasterKey::new(key);
        let ck = mk.constrained(2000..2000+i);
        group.bench_function(BenchmarkId::new("evalate for each", i), |b| b.iter(|| (ck.get_range().0..=ck.get_range().1).for_each(|x| {ck.evaluate(black_box(x));})));
        group.bench_function(BenchmarkId::new("evalate_all", i), |b| b.iter(|| ck.evaluate_all().for_each(|_| ())));
    }
}

criterion_group!(benches, bench_fibs, bench_ggm_evaluate_all);
criterion_main!(benches);