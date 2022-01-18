mod store;
mod wire_trie;

pub use crate::wire_trie::{Digest, WireTrieRef, DIGEST_LENGTH};

#[cfg(test)]
mod tests {
    use crate::{
        store::{
            updater::{Node, OwnedTrie, Updater, UpdatingTrie},
            InMemoryArchivalStore,
        },
        wire_trie::{TrieRead, WireTrieLeafRef, EMPTY_DIGEST, NODE31_TAG},
        Digest, WireTrieRef,
    };

    fn node_with_one_branch(branch_idx: u8) -> Node {
        let mut node = Node::new_empty(vec![0, 1, 2]);
        node.swap_new_branch_at_idx(branch_idx, &mut UpdatingTrie::digest([1u8; 32]));
        node
    }

    #[test]
    fn trie_bytes_from_node_with_one_branch() {
        let node = node_with_one_branch(0);
        let trie_bytes = OwnedTrie::try_from(&node).expect("should convert to trie bytes");
        assert_eq!(trie_bytes.raw_bytes()[0] >> 5, NODE31_TAG);
        assert_eq!(trie_bytes.raw_bytes()[0] & 0b11111, 1);
    }

    #[test]
    fn node_with_one_branch_round_trip() {
        for branch_idx in 0..=255 {
            let node = node_with_one_branch(branch_idx);
            let owned_trie = OwnedTrie::try_from(&node).expect("should convert to trie bytes");
            let expected = UpdatingTrie::node(node_with_one_branch(branch_idx));
            let parsed = UpdatingTrie::try_from(&owned_trie).expect("should convert to FancyTrie");
            assert_eq!(expected, parsed, "Bad idx: {}", branch_idx)
        }
    }

    #[test]
    fn updating_trie_is_small() {
        let size = std::mem::size_of::<UpdatingTrie>();
        assert_eq!(size, 8, "FancyTrie bytes")
    }

    #[test]
    fn option_box_updating_trie_is_small() {
        let size = std::mem::size_of::<Option<Box<UpdatingTrie>>>();
        assert_eq!(size, 16, "FancyTrie bytes")
    }

    #[test]
    #[should_panic]
    fn updater_throws_if_one_key_is_a_prefix_of_another() {
        let mut store = InMemoryArchivalStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
        let key1 = vec![0, 1, 2, 3];
        let key2 = vec![0, 1, 2];
        let value = vec![0, 1, 2, 3];
        updater
            .put(key1.clone(), value.clone())
            .expect("Could not put");
        updater
            .put(key2.clone(), value.clone())
            .expect("Should panic here because key2 is a prefix of key1");
    }

    #[test]
    fn put_two_keys_and_read_back_from_storage() {
        let mut store = InMemoryArchivalStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
        let key1 = vec![0, 1, 2, 3];
        let key2 = vec![0, 1, 2, 4];
        let value = vec![0, 1, 2, 3];
        updater
            .put(key1.clone(), value.clone())
            .expect("Could not put");
        updater
            .put(key2.clone(), value.clone())
            .expect("Could not put");
        let root = updater.commit();
        let expected_keys = vec![key1, key2];
        let keys_from_storage: Vec<Vec<u8>> = store
            .iterate_leaves_under_prefix(root, vec![])
            .map(|leaf: WireTrieLeafRef| leaf.key().to_owned())
            .collect();
        assert_eq!(expected_keys, keys_from_storage)
    }

    #[test]
    fn put_three_keys_iterate_with_prefix() {
        let mut store = InMemoryArchivalStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
        let key1 = vec![0, 1, 2, 3];
        let key2 = vec![0, 1, 2, 4];
        let key3 = vec![0, 1, 3, 3];
        let value = vec![0, 1, 2, 3];
        updater
            .put(key1.clone(), value.clone())
            .expect("Could not put");
        updater
            .put(key2.clone(), value.clone())
            .expect("Could not put");
        updater
            .put(key3.clone(), value.clone())
            .expect("Could not put");
        let root = updater.commit();
        let expected_keys = vec![key1, key2];
        let keys_from_storage: Vec<Vec<u8>> = store
            .iterate_leaves_under_prefix(root, vec![0, 1, 2])
            .map(|leaf: WireTrieLeafRef| leaf.key().to_owned())
            .collect();
        assert_eq!(expected_keys, keys_from_storage)
    }

    #[test]
    fn palindrome_update() {
        let palindrome_keys: [[u8; 3]; 3] = [[0, 0, 0], [0, 0, 1], [0, 0, 0]];

        let mut store = InMemoryArchivalStore::new();

        let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
        palindrome_keys
            .iter()
            .for_each(|key| updater.put(key.to_vec(), vec![0u8]).expect("Could not put"));
        let _ = updater.commit();
    }

    #[test]
    fn max_key_bytes_update() {
        let keys = [vec![0], vec![255, 0], vec![255, 1]];

        let mut store = InMemoryArchivalStore::new();

        let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
        keys.iter()
            .for_each(|key| updater.put(key.to_vec(), vec![0u8]).expect("Could not put"));
        let _ = updater.commit();
    }

    #[test]
    fn small_binary_tree() {
        let keys = [[0, 0], [0, 1], [1, 0], [1, 1]];

        let mut store = InMemoryArchivalStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
        keys.iter()
            .for_each(|key| updater.put(key.to_vec(), vec![0u8]).expect("Could not put"));
        let _ = updater.commit();
    }

    #[test]
    fn iterating_down_to_leaves() {
        let keys: [[u8; 4]; 10] = [
            [0, 1, 2, 3],
            [0, 1, 2, 0],
            [0, 1, 0, 0],
            [0, 0, 0, 0],
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            [3, 3, 3, 3],
            [0, 1, 1, 1],
            [0, 0, 2, 2],
            [0, 0, 0, 3],
        ];

        let mut store = InMemoryArchivalStore::new();

        let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
        keys.iter()
            .for_each(|key| updater.put(key.to_vec(), vec![0u8]).expect("Could not put"));
        let root = updater.commit();

        for key in keys {
            let keys_from_storage: Vec<Vec<u8>> = store
                .iterate_leaves_under_prefix(root, key.to_vec())
                .map(|leaf: WireTrieLeafRef| leaf.key().to_owned())
                .collect();
            assert_eq!(vec![key.to_vec()], keys_from_storage)
        }
    }

    // TODO: Test putting keys (updating along the way) and putting in keys (updating along the way)
    // and getting the same resulting state root
    //
    // TODO: Test reading with proof
    // TODO: Test iterating with a non-empty prefix
    // TODO: Test do-nothing updater on EMPTY_DIGEST
    // TODO: Test do-nothing updater on Some digest

    mod proptests {
        use crate::{
            store::{updater::Updater, InMemoryArchivalStore},
            wire_trie::EMPTY_DIGEST,
        };
        use test_strategy::proptest;

        #[proptest]
        fn reverse_insert_is_the_same(keys: [[u8; 5]; 10]) {
            let mut store = InMemoryArchivalStore::new();

            let forward_digest = {
                let mut forward_updater = Updater::new(&mut store, EMPTY_DIGEST);
                keys.iter().for_each(|key| {
                    forward_updater
                        .put(key.to_vec(), vec![0u8])
                        .expect("Could not put")
                });
                forward_updater.commit()
            };

            let reverse_digest = {
                let mut reverse_updater = Updater::new(&mut store, EMPTY_DIGEST);
                keys.iter().rev().for_each(|key| {
                    reverse_updater
                        .put(key.to_vec(), vec![0u8])
                        .expect("Could not put")
                });
                reverse_updater.commit()
            };

            assert_eq!(forward_digest, reverse_digest)
        }

        #[proptest]
        fn insert_and_insert_again_same_as_once(keys1: [[u8; 5]; 30], keys2: [[u8; 5]; 30]) {
            let mut store = InMemoryArchivalStore::new();

            let insert_all_at_once_digest = {
                let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
                keys1
                    .iter()
                    .chain(keys2.iter())
                    .for_each(|key| updater.put(key.to_vec(), vec![0u8]).expect("Could not put"));
                updater.commit()
            };

            let insert_and_insert_again_digest = {
                let mut updater = Updater::new(&mut store, EMPTY_DIGEST);
                keys1
                    .iter()
                    .for_each(|key| updater.put(key.to_vec(), vec![0u8]).expect("Could not put"));
                let digest = updater.commit();
                let mut updater = Updater::new(&mut store, digest);
                keys2
                    .iter()
                    .for_each(|key| updater.put(key.to_vec(), vec![0u8]).expect("Could not put"));
                updater.commit()
            };

            assert_eq!(insert_all_at_once_digest, insert_and_insert_again_digest)
        }
    }
}
