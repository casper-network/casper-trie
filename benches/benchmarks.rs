use criterion::{criterion_group, criterion_main, Criterion};

use trie::{
    store::{updater::Updater, InMemoryStore},
    EMPTY_TRIE_ROOT,
};

pub fn criterion_benchmark(c: &mut Criterion) {
    // LCG from https://www.ams.org/journals/mcom/1999-68-225/S0025-5718-99-00996-5/S0025-5718-99-00996-5.pdf
    let a: u128 = 82461096547334812307256211668490605096;
    let m: u128 = (1 << 64) - 59;

    c.bench_function("Store 10_000 leaves", |b| {
        b.iter(|| {
            let mut store = InMemoryStore::new();
            let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
            let mut x: u128 = a;
            for _ in 0..10_000 {
                x = x.saturating_add(a) % m;
                updater
                    .put((x as u64).to_le_bytes().as_ref(), &[])
                    .expect("could not put");
            }
            updater.commit();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
