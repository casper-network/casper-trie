pub mod store;
mod wire_trie;

pub use crate::wire_trie::{Digest, Trie, DIGEST_LENGTH, EMPTY_TRIE_ROOT};

#[cfg(test)]
mod tests {
    use crate::{
        store::{
            updater::{Node, OwnedTrie, Updater, UpdatingTrie, MAX_KEY_BYTES_LEN},
            InMemoryStore, TrieReader,
        },
        wire_trie::{TrieTag, EMPTY_TRIE_ROOT},
        Digest,
    };

    fn node_with_one_branch(branch_idx: u8) -> Node {
        let mut node = Node::new_empty(vec![0, 1, 2]);
        node.swap_new_branch_at_idx(branch_idx, &mut UpdatingTrie::digest([1u8; 32]));
        node
    }

    #[test]
    fn trie_bytes_from_node_with_one_branch() {
        let node = node_with_one_branch(0);
        let trie_bytes = OwnedTrie::try_from(&node).expect("Should convert to trie bytes");
        assert_eq!(trie_bytes.as_ref()[0] >> 5, TrieTag::Node31 as u8);
        assert_eq!(trie_bytes.as_ref()[0] & 0b11111, 1);
    }

    #[test]
    fn node_with_one_branch_round_trip() {
        for branch_idx in 0..=MAX_KEY_BYTES_LEN {
            let node = node_with_one_branch(branch_idx);
            let owned_trie = OwnedTrie::try_from(&node).expect("Should convert to trie bytes");
            let expected = UpdatingTrie::node(node_with_one_branch(branch_idx));
            let parsed =
                UpdatingTrie::try_from(&owned_trie).expect("Should convert to UpdatingTrie");
            assert_eq!(expected, parsed, "Bad idx: {}", branch_idx)
        }
    }

    #[test]
    #[ignore]
    fn updating_trie_is_small() {
        let size = std::mem::size_of::<UpdatingTrie>();
        assert_eq!(size, 8, "UpdatingTrie bytes")
    }

    #[test]
    #[ignore]
    fn option_box_updating_trie_is_small() {
        let size = std::mem::size_of::<Option<Box<UpdatingTrie>>>();
        assert_eq!(size, 16, "UpdatingTrie bytes")
    }

    #[test]
    #[should_panic]
    fn updater_throws_if_one_key_is_a_prefix_of_another() {
        let mut store = InMemoryStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let key1 = vec![0, 1, 2, 3];
        let key2 = vec![0, 1, 2];
        let value = vec![0, 1, 2, 3];
        updater
            .put(key1.as_ref(), value.as_ref())
            .expect("Could not put");
        updater
            .put(key2.as_ref(), value.as_ref())
            .expect("Should panic here because key2 is a prefix of key1");
    }

    #[test]
    fn put_two_keys_and_read_back_from_storage() {
        let mut store = InMemoryStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let key1 = vec![0, 1, 2, 3];
        let key2 = vec![0, 1, 2, 4];
        let value = vec![0, 1, 2, 3];
        updater
            .put(key1.as_ref(), value.as_ref())
            .expect("Could not put");
        updater
            .put(key2.as_ref(), value.as_ref())
            .expect("Could not put");
        let root = updater.commit().expect("Could not commit");
        let expected_keys = vec![key1, key2];
        let keys_from_storage: Vec<Vec<u8>> = store
            .leaves_under_prefix(root, vec![])
            .map(|leaf_result| leaf_result.expect("Could not get leaf").key().to_owned())
            .collect();
        assert_eq!(expected_keys, keys_from_storage)
    }

    #[test]
    fn put_three_keys_iterate_with_prefix() {
        let mut store = InMemoryStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let key1 = vec![0, 1, 2, 3];
        let key2 = vec![0, 1, 2, 4];
        let key3 = vec![0, 1, 3, 3];
        let value = vec![0, 1, 2, 3];
        updater
            .put(key1.as_ref(), value.as_ref())
            .expect("Could not put");
        updater
            .put(key2.as_ref(), value.as_ref())
            .expect("Could not put");
        updater
            .put(key3.as_ref(), value.as_ref())
            .expect("Could not put");
        let root = updater.commit().expect("Could not commit");
        let expected_keys = vec![key1, key2];
        let keys_from_storage: Vec<Vec<u8>> = store
            .leaves_under_prefix(root, vec![0, 1, 2])
            .map(|leaf_result| leaf_result.expect("Could not get leaf").key().to_owned())
            .collect();
        assert_eq!(expected_keys, keys_from_storage)
    }

    #[test]
    fn palindrome_update() {
        let palindrome_keys: [[u8; 3]; 3] = [[0, 0, 0], [0, 0, 1], [0, 0, 0]];

        let mut store = InMemoryStore::new();

        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        palindrome_keys.iter().for_each(|key| {
            updater
                .put(key.as_ref(), [0u8].as_ref())
                .expect("Could not put")
        });
        let _ = updater.commit();
    }

    #[test]
    fn max_key_bytes_update() {
        let keys = [vec![0], vec![255, 0], vec![255, 1]];

        let mut store = InMemoryStore::new();

        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        keys.iter().for_each(|key| {
            updater
                .put(key.as_ref(), [0u8].as_ref())
                .expect("Could not put")
        });
        let _ = updater.commit();
    }

    #[test]
    fn small_binary_tree() {
        let keys = [[0, 0], [0, 1], [1, 0], [1, 1]];

        let mut store = InMemoryStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        keys.iter().for_each(|key| {
            updater
                .put(key.as_ref(), [0u8].as_ref())
                .expect("Could not put")
        });
        let _ = updater.commit();
    }

    #[test]
    fn iterating_down_to_leaves_pair() {
        let keys = [[0, 1, 0, 0], [0, 0, 0, 0]];

        let mut store = InMemoryStore::new();

        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        keys.iter().for_each(|key| {
            updater
                .put(key.as_ref(), [0u8].as_ref())
                .expect("Could not put")
        });
        let root = updater.commit().expect("Could not commit");

        for key in keys {
            let keys_from_storage: Vec<Vec<u8>> = store
                .leaves_under_prefix(root, key.to_vec())
                .map(|leaf_result| leaf_result.expect("Could not get leaf").key().to_owned())
                .collect();
            assert_eq!(vec![key.as_ref()], keys_from_storage)
        }
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

        let mut store = InMemoryStore::new();

        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        keys.iter().for_each(|key| {
            updater
                .put(key.as_ref(), [0u8].as_ref())
                .expect("Could not put")
        });
        let root = updater.commit().expect("Could not commit");

        for key in keys {
            let keys_from_storage: Vec<Vec<u8>> = store
                .leaves_under_prefix(root, key.to_vec())
                .map(|leaf_result| leaf_result.expect("Could not get leaf").key().to_owned())
                .collect();
            assert_eq!(vec![key.as_ref()], keys_from_storage)
        }
    }

    #[test]
    fn empty_trie() {
        let mut store = InMemoryStore::new();
        let updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let root = updater.commit().expect("Could not commit");
        assert_eq!(root, EMPTY_TRIE_ROOT)
    }

    #[test]
    fn empty_leaf_iterator() {
        let mut store = InMemoryStore::new();
        let updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let root = updater.commit().expect("Could not commit");
        let leaves: Vec<_> = store.leaves_under_prefix(root, vec![]).collect();
        dbg!(&leaves);
        assert!(leaves.is_empty())
    }

    #[test]
    fn find_missing_descendants_trie_with_just_one_thing() {
        let keys = [[0u8, 0, 0, 0, 0]];
        let mut store = InMemoryStore::new();
        let mut forward_updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        keys.iter().for_each(|key| {
            forward_updater
                .put(key.as_ref(), [0u8].as_ref())
                .expect("Could not put")
        });
        let root = forward_updater.commit().expect("Could not commit");
        let missing_trie_digests: Vec<Digest> = store
            .find_missing_trie_descendants(root)
            .map(|missing_descendant| missing_descendant.expect("Error getting missing descendant"))
            .collect::<Vec<_>>();
        assert_eq!(missing_trie_digests, Vec::<Digest>::new());
    }

    #[test]
    fn find_missing_descendants_trie_with_several_things() {
        let keys = [
            [0u8, 0, 0, 0, 0],
            [0, 0, 0, 0, 1],
            [0, 0, 0, 1, 0],
            [0, 0, 0, 1, 1],
            [0, 0, 1, 0, 0],
            [0, 0, 1, 0, 1],
            [0, 0, 1, 1, 0],
            [0, 0, 1, 1, 1],
            [0, 1, 0, 0, 0],
            [0, 1, 0, 0, 1],
            [0, 1, 0, 1, 0],
            [0, 1, 0, 1, 1],
            [0, 1, 1, 0, 0],
            [0, 1, 1, 0, 1],
            [0, 1, 1, 1, 0],
            [0, 1, 1, 1, 1],
            [1, 0, 0, 0, 0],
        ];
        let mut store = InMemoryStore::new();
        let mut forward_updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        keys.iter().for_each(|key| {
            forward_updater
                .put(key.as_ref(), [0u8].as_ref())
                .expect("Could not put")
        });
        let root = forward_updater.commit().expect("Could not commit");
        let missing_trie_digests: Vec<Digest> = store
            .find_missing_trie_descendants(root)
            .map(|missing_descendant| missing_descendant.expect("Error getting missing descendant"))
            .collect::<Vec<_>>();
        assert_eq!(missing_trie_digests, Vec::<Digest>::new());
    }

    #[test]
    fn find_missing_descendants_empty_keys() {
        let mut store = InMemoryStore::new();
        let updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let root = updater.commit().expect("Could not commit");
        let missing_trie_digests = store
            .find_missing_trie_descendants(root)
            .map(|missing_descendant| {
                missing_descendant.expect("Error getting missing trie descendant")
            })
            .collect::<Vec<_>>();
        assert_eq!(missing_trie_digests, Vec::<Digest>::new())
    }

    // TODO: Test putting keys (updating along the way) and putting in keys (updating along the way)
    // and getting the same resulting state root
    //
    // TODO: Test reading with proof
    // TODO: Test iterating with a non-empty prefix
    // TODO: Test do-nothing updater on Some digest

    mod proptests {
        use crate::{
            store::{
                updater::{OwnedTrie, Updater, MAX_KEY_BYTES_LEN},
                InMemoryStore, TrieReader, TrieWriter,
            },
            wire_trie::EMPTY_TRIE_ROOT,
            Digest,
        };
        use std::collections::{BTreeSet, HashSet};
        use test_strategy::proptest;

        impl OwnedTrie {
            pub(crate) fn get_nth_digest(
                &self,
                n: u8,
            ) -> Result<crate::wire_trie::TrieLeafOrBranch, crate::wire_trie::TrieReadError>
            {
                self.as_trie().get_nth_digest(n)
            }

            pub(crate) fn version_byte_and_envelope_hash(&self) -> blake3::Hash {
                self.as_trie().version_byte_and_envelope_hash()
            }
        }

        #[proptest]
        fn reverse_insert_is_the_same(keys: [[u8; 5]; 10]) {
            let mut store = InMemoryStore::new();

            let forward_digest = {
                let mut forward_updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                keys.iter().for_each(|key| {
                    forward_updater
                        .put(key.as_ref(), [0u8].as_ref())
                        .expect("Could not put")
                });
                forward_updater.commit().expect("Could not commit")
            };

            let reverse_digest = {
                let mut reverse_updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                keys.iter().rev().for_each(|key| {
                    reverse_updater
                        .put(key.as_ref(), [0u8].as_ref())
                        .expect("Could not put")
                });
                reverse_updater.commit().expect("Could not commit")
            };

            assert_eq!(forward_digest, reverse_digest)
        }

        #[proptest]
        fn insert_and_insert_again_same_as_once(keys1: [[u8; 5]; 30], keys2: [[u8; 5]; 30]) {
            let mut store = InMemoryStore::new();

            let insert_all_at_once_digest = {
                let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                keys1.iter().chain(keys2.iter()).for_each(|key| {
                    updater
                        .put(key.as_ref(), [0u8].as_ref())
                        .expect("Could not put")
                });
                updater.commit().expect("Could not commit")
            };

            let insert_and_insert_again_digest = {
                let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                keys1.iter().for_each(|key| {
                    updater
                        .put(key.as_ref(), [0u8].as_ref())
                        .expect("Could not put")
                });
                let digest = updater.commit().expect("Could not commit");
                let mut updater = Updater::new(&mut store, digest);
                keys2.iter().for_each(|key| {
                    updater
                        .put(key.as_ref(), [0u8].as_ref())
                        .expect("Could not put")
                });
                updater.commit().expect("Could not commit")
            };

            assert_eq!(insert_all_at_once_digest, insert_and_insert_again_digest)
        }

        #[proptest]
        fn prefix_iterator(prefix: Vec<u8>, keys: BTreeSet<[u8; 10]>) {
            let keys = keys.into_iter().collect::<Vec<_>>();

            let mut store = InMemoryStore::new();

            let root = {
                let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                for key in &keys {
                    updater
                        .put(key.as_ref(), [0u8].as_ref())
                        .expect("Could not put");
                }
                updater.commit().expect("Could not commit")
            };

            let expected: Vec<_> = keys
                .into_iter()
                .filter(|key| key.starts_with(&prefix))
                .collect();
            let actual: Vec<[u8; 10]> = store
                .leaves_under_prefix(root, prefix)
                .map(|leaf_result| {
                    leaf_result
                        .expect("Could not get leaf")
                        .key()
                        .try_into()
                        .expect("Could not convert trie leaf key to [u8; 10]")
                })
                .collect();

            assert_eq!(expected, actual)
        }

        #[proptest]
        fn prefix_iterator_bool(prefix: Vec<bool>, keys: BTreeSet<[bool; 10]>) {
            let keys: Vec<Vec<u8>> = keys
                .into_iter()
                .map(|key| {
                    key.into_iter()
                        .map(|bit| if bit { 1u8 } else { 0u8 })
                        .collect::<Vec<u8>>()
                })
                .collect();
            let prefix: Vec<u8> = prefix
                .into_iter()
                .map(|bit| if bit { 1u8 } else { 0u8 })
                .collect();

            let mut store = InMemoryStore::new();

            let root = {
                let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                for key in &keys {
                    updater
                        .put(key.as_ref(), [0u8].as_ref())
                        .expect("Could not put");
                }
                updater.commit().expect("Could not commit")
            };

            let expected: Vec<_> = keys
                .into_iter()
                .filter(|key| key.starts_with(&prefix))
                .collect();
            let actual: Vec<Vec<u8>> = store
                .leaves_under_prefix(root, prefix)
                .map(|leaf_result| {
                    leaf_result
                        .expect("Could not get leaf")
                        .key()
                        .try_into()
                        .expect("Could not convert trie leaf key to [u8; 10]")
                })
                .collect();

            assert_eq!(expected, actual)
        }

        #[proptest]
        fn variable_length_keys(keys: HashSet<Vec<u8>>) {
            let mut keys: Vec<Vec<u8>> = keys.into_iter().collect();
            keys.iter_mut()
                .for_each(|key| key.truncate(MAX_KEY_BYTES_LEN as usize));
            keys.sort();

            let mut store = InMemoryStore::new();

            let root = {
                let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                for key in &keys {
                    let mut prefixed_key = vec![key.len() as u8];
                    prefixed_key.extend(key);
                    updater
                        .put(&prefixed_key, [0u8].as_ref())
                        .expect("Could not put");
                }
                updater.commit().expect("Could not commit")
            };

            let mut retrieved_keys: Vec<Vec<u8>> = store
                .leaves_under_prefix(root, vec![])
                .map(|leaf_result| leaf_result.expect("Could not get leaf").key()[1..].to_vec())
                .collect();
            retrieved_keys.sort();
            assert_eq!(keys, retrieved_keys)
        }

        #[proptest]
        fn find_missing_descendants_full_tries(keys: Vec<[u8; 5]>) {
            let mut store = InMemoryStore::new();
            let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
            keys.iter().for_each(|key| {
                updater
                    .put(key.as_ref(), [0u8].as_ref())
                    .expect("Could not put")
            });
            let root = updater.commit().expect("Could not commit");
            let missing_trie_digests: Vec<Digest> = store
                .find_missing_trie_descendants(root)
                .map(|missing_descendant| {
                    missing_descendant.expect("Error getting missing trie descendant")
                })
                .collect::<Vec<_>>();
            assert_eq!(missing_trie_digests, Vec::<Digest>::new());
        }

        #[proptest]
        fn copy_one_trie_to_another(keys_value_pairs: Vec<([u8; 5], [u8; 5])>) {
            let mut store = InMemoryStore::new();

            let mut roots = vec![EMPTY_TRIE_ROOT];
            roots.extend(keys_value_pairs.iter().map(|(key, value)| {
                let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
                updater.put(key, value).expect("Could not put");
                updater.commit().expect("Could not commit")
            }));

            let mut store2 = InMemoryStore::new();
            for root_to_be_copied in roots.iter() {
                let mut keep_going = true;
                while keep_going {
                    keep_going = false;
                    let missing_descendant_trie_digests = store2
                        .find_missing_trie_descendants(root_to_be_copied.to_owned())
                        .map(|missing_trie_digest| {
                            missing_trie_digest.expect("Trie digest is missing")
                        })
                        .collect::<Vec<_>>();
                    for missing_trie_digest in missing_descendant_trie_digests {
                        keep_going = true;
                        store2
                            .put_trie(
                                missing_trie_digest,
                                store
                                    .get_trie(&missing_trie_digest)
                                    .expect("Could not get trie")
                                    .expect("Trie should not be missing"),
                            )
                            .expect("Could not put trie");
                    }
                }

                let expected_key_values = store
                    .leaves_under_prefix(root_to_be_copied.to_owned(), vec![])
                    .map(|leaf_result| {
                        let leaf = leaf_result.expect("Could not get leaf");
                        (leaf.key().to_owned(), leaf.value().to_owned())
                    })
                    .collect::<Vec<_>>();

                let actual_key_values = store2
                    .leaves_under_prefix(root_to_be_copied.to_owned(), vec![])
                    .map(|leaf_result| {
                        let leaf = leaf_result.expect("Could not get leaf");
                        (leaf.key().to_owned(), leaf.value().to_owned())
                    })
                    .collect::<Vec<_>>();

                assert_eq!(expected_key_values, actual_key_values);
            }
        }
    }
}
