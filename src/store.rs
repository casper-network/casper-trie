mod fast_sync;
mod garbage_collect;

pub(crate) mod updater;
use crate::{
    store::updater::{OwnedTrie, Updater, UpdatingTrie},
    wire_trie::{
        TrieRead, TrieReadWithProof, WireTrieLeafRef, EMPTY_DIGEST, LEAF_TAG, NODE256_TAG,
        NODE31_TAG,
    },
    Digest, WireTrieRef,
};
use std::collections::HashMap;

// TODO: wrap rocksdb - talk to Dan

// TODO: struct Ref(u64)
// TODO struct Store { roots: HashMap<Digest, Ref>, tries: HashMap<Ref, Vec<u8>> }

#[derive(Debug)]
// TODO: Make trait, move to test
pub(crate) struct InMemoryArchivalStore(HashMap<Digest, Vec<u8>>);

impl InMemoryArchivalStore {
    // TODO: Public interface: get and put_many

    pub(crate) fn new() -> InMemoryArchivalStore {
        InMemoryArchivalStore(HashMap::new())
    }

    fn get_trie_ref(&self, digest: &Digest) -> Option<WireTrieRef> {
        self.0
            .get(digest)
            .map(|trie_bytes| WireTrieRef::new(&*trie_bytes))
    }

    fn put_trie(&mut self, digest: Digest, owned_trie: OwnedTrie) {
        self.0.insert(digest, owned_trie.into());
    }

    // TODO: Bulk trie retrieve  fn bulk_trie_download(root: Digest, prefixes: Vec<Vec<u8>>,
    // missing_descendants: Vec<Digest>, bloom_filter: BloomFilter) ->
    // Result<Vec<WireTrie>,DigestNotUnderPrefix> TODO: Read with proof
    // TODO: TODO rethink find_missing_descendants

    pub fn iterate_leaves_under_prefix(
        &self,
        root: Digest,
        prefix: Vec<u8>,
    ) -> TrieLeavesUnderPrefixIterator {
        let node_stack = if prefix.is_empty() {
            vec![(root.clone(), 0)]
        } else {
            vec![]
        };
        TrieLeavesUnderPrefixIterator {
            root,
            prefix,
            store: &self,
            node_stack,
        }
    }
}

pub struct TrieLeavesUnderPrefixIterator<'a> {
    root: Digest,
    prefix: Vec<u8>,
    store: &'a InMemoryArchivalStore,
    node_stack: Vec<(Digest, u8)>,
}

impl<'a> Iterator for TrieLeavesUnderPrefixIterator<'a> {
    type Item = WireTrieLeafRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.prefix.is_empty() {
            self.node_stack.clear();
            let mut current_lookup_digest = self.root.clone();
            let mut prefix_bytes_read: u8 = 0;
            loop {
                let trie = match self.store.get_trie_ref(&current_lookup_digest) {
                    Some(trie) => trie,
                    None => {
                        // Could not look up digest. The trie-store is likely corrupted.
                        // Stop iterating.
                        self.prefix.clear();
                        self.node_stack.clear();
                        return None;
                    }
                };

                let common_prefix_count = trie
                    .key_or_affix()
                    .iter()
                    .zip(self.prefix[prefix_bytes_read as usize..].iter())
                    .take_while(|(byte1, byte2)| byte1 == byte2)
                    .count();

                if prefix_bytes_read as usize + common_prefix_count == self.prefix.len() {
                    match trie.tag() {
                        // The only node beyond our prefix is a leaf.
                        // We'll return this and stop the iterator.
                        LEAF_TAG => {
                            self.prefix.clear();
                            self.node_stack.clear();
                            return Some(WireTrieLeafRef::new(&trie.raw_bytes()[1..]));
                        }
                        // We have hit a node. Start iterating through its branches.
                        NODE31_TAG | NODE256_TAG => break,
                        // This is an error condition, stop iterating.
                        _ => {
                            self.prefix.clear();
                            self.node_stack.clear();
                            return None;
                        }
                    }
                }
                if let Ok(TrieReadWithProof::DigestWithProof {
                    digest,
                    key_bytes_read,
                    ..
                }) = trie.read_using_search_key(&self.prefix, prefix_bytes_read)
                {
                    prefix_bytes_read = key_bytes_read;
                    current_lookup_digest = digest.clone();
                } else {
                    self.prefix.clear();
                    self.node_stack.clear();
                    return None;
                }
            }
            self.prefix.clear();
            self.node_stack.push((current_lookup_digest, 0))
        }

        while let Some((node_digest, branch_idx)) = self.node_stack.pop() {
            let trie = match self.store.get_trie_ref(&node_digest) {
                Some(trie) => trie,
                None => {
                    self.node_stack.clear();
                    return None;
                }
            };
            match trie.get_nth_digest(branch_idx) {
                Ok(TrieRead::NotFound) => continue,
                Ok(TrieRead::TrieLeaf(leaf)) => {
                    return Some(leaf);
                }
                Ok(TrieRead::DigestReadFromNode(new_digest)) => {
                    self.node_stack.push((node_digest, branch_idx + 1));
                    self.node_stack.push((new_digest.clone(), 0));
                }
                Err(_) => {
                    self.node_stack.clear();
                    return None;
                }
            }
        }
        None
    }
}
