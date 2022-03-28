mod fast_sync;
mod garbage_collect;

mod backends;
pub(crate) mod updater;

pub use crate::store::backends::in_memory::InMemoryStore;
use crate::{
    wire_trie::{Leaf, Tag, Trie, TrieLeafOrBranch},
    Digest,
};

// TODO: wrap rocksdb - talk to Dan

// TODO: struct Ref(u64)
// TODO struct Store { roots: HashMap<Digest, Ref>, tries: HashMap<Ref, Vec<u8>> }

pub trait TrieStore {
    fn get_trie(&self, digest: &Digest) -> Option<Trie>;
}

pub struct TrieLeavesUnderPrefixIterator<'a, 'b, S> {
    root: Digest,
    store: &'a S,
    prefix: &'b [u8],
    initialized: bool,
    node_stack: Vec<(Digest, u8)>,
}

impl<'a, 'b, S> Iterator for TrieLeavesUnderPrefixIterator<'a, 'b, S>
where
    S: TrieStore,
{
    type Item = Leaf<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.initialized {
            let mut current_lookup_digest = self.root;
            let mut prefix_bytes_read: u8 = 0;
            loop {
                let trie = match self.store.get_trie(&current_lookup_digest) {
                    Some(trie) => trie,
                    None => {
                        // Could not look up digest. The trie-store may be corrupted.
                        // Stop iterating.
                        self.initialized = true;
                        return None;
                    }
                };

                if trie.tag() == Tag::Leaf {
                    self.initialized = true;
                    if trie.key_or_affix().starts_with(self.prefix) {
                        return Some(Leaf::new(trie));
                    } else {
                        return None;
                    }
                }

                let common_prefix_count = trie
                    .key_or_affix()
                    .iter()
                    .zip(self.prefix[prefix_bytes_read as usize..].iter())
                    .take_while(|(byte1, byte2)| byte1 == byte2)
                    .count();

                if prefix_bytes_read as usize + common_prefix_count == self.prefix.len() {
                    break;
                }
                if let Ok(TrieLeafOrBranch::Branch(digest)) =
                    trie.read_using_search_key(self.prefix, &mut prefix_bytes_read)
                {
                    current_lookup_digest = *digest;
                } else {
                    self.initialized = true;
                    return None;
                }
            }
            self.initialized = true;
            self.node_stack.push((current_lookup_digest, 0))
        }

        while let Some((node_digest, branch_idx)) = self.node_stack.pop() {
            let trie = match self.store.get_trie(&node_digest) {
                Some(trie) => trie,
                None => {
                    self.node_stack.clear();
                    return None;
                }
            };
            match trie.get_nth_digest(branch_idx) {
                Ok(TrieLeafOrBranch::Leaf(leaf)) => {
                    return Some(leaf);
                }
                Ok(TrieLeafOrBranch::Branch(new_digest)) => {
                    self.node_stack.push((node_digest, branch_idx + 1));
                    self.node_stack.push((*new_digest, 0));
                }
                Ok(TrieLeafOrBranch::IndexOutOfRange | TrieLeafOrBranch::KeyNotFound) => continue,
                Err(_) => {
                    self.node_stack.clear();
                    return None;
                }
            }
        }
        None
    }
}
