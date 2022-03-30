use crate::{
    store::{updater::OwnedTrie, TrieLeavesUnderPrefixIterator, TrieStore},
    Digest, Trie,
};
use std::{collections::HashMap, convert::Infallible};

#[derive(Debug)]
pub struct InMemoryStore(HashMap<Digest, Vec<u8>>);

impl TrieStore for InMemoryStore {
    type Error = Infallible;

    fn get_trie(&self, digest: &Digest) -> Result<Option<Trie>, Self::Error> {
        Ok(self.0.get(digest).map(|trie_bytes| Trie::new(&*trie_bytes)))
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    // TODO: Public interface: get and put_many

    pub fn new() -> InMemoryStore {
        InMemoryStore(HashMap::new())
    }

    pub(crate) fn put_trie(&mut self, digest: Digest, owned_trie: OwnedTrie) {
        self.0.insert(digest, owned_trie.into());
    }

    // fn bulk_trie_download(
    //   root: Digest,
    //   prefixes: Vec<Vec<u8>>,
    //   missing_descendants: Vec<Digest>,
    //   bloom_filter: BloomFilter) -> Result<Vec<WireTrie>, DigestNotUnderPrefix>
    // TODO: Read with proof
    // TODO: rethink find_missing_descendants
    // TODO: Bulk trie retrieve
    pub fn leaves_under_prefix<'a, 'b>(
        &'a self,
        root: Digest,
        prefix: &'b [u8],
    ) -> TrieLeavesUnderPrefixIterator<'a, 'b, Self> {
        TrieLeavesUnderPrefixIterator {
            root,
            store: self,
            prefix,
            initialized: false,
            node_stack: vec![],
        }
    }
}
