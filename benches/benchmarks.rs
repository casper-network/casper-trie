use criterion::{criterion_group, criterion_main, Criterion};
use trie::{FancyTrie, Node, OwnedTrie};

fn node_with_n_branches(branch_count: u8, offset: u8, spacing: u8) -> Node {
    let mut node = Node::new_empty(vec![0, 1, 2]);
    if spacing == 0 {
        for branch_idx in offset..offset + branch_count {
            node.swap_insert_branch_at_idx(
                branch_idx,
                &mut FancyTrie::digest([(branch_idx % 8) as u8; 32]),
            );
        }
    } else {
        for branch_idx in (offset..offset + spacing * branch_count).step_by(spacing as usize) {
            node.swap_insert_branch_at_idx(
                branch_idx,
                &mut FancyTrie::Digest(Box::new([(branch_idx % 8) as u8; 32])),
            );
        }
    };
    node
}

// TODO: Write a benchmark with updater, don't do this so we can keep OwnedTrie private
pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("build and parse a 200 branch Node", |b| {
        b.iter(|| {
            let node = node_with_n_branches(200, 20, 0);
            let owned_trie = OwnedTrie::try_from(node).expect("should convert to trie bytes");
            FancyTrie::try_from(&owned_trie).expect("should convert to FancyTrie")
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
