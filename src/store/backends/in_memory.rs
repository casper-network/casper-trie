use std::{collections::HashMap, convert::Infallible};

use crate::store::{TransactionError, TrieTransactional, TrieWriter};
use crate::{store::TrieReader, Digest, Trie};

#[derive(Debug)]
pub struct InMemoryStore(HashMap<Digest, Vec<u8>>);

impl TrieReader for InMemoryStore {
    type Error = Infallible;

    fn get_trie(&self, digest: &Digest) -> Result<Option<Trie>, Self::Error> {
        Ok(self
            .0
            .get(digest)
            .map(|trie_bytes| Trie::new(trie_bytes.as_ref())))
    }
}

impl TrieWriter for InMemoryStore {
    type Error = Infallible;

    fn put_trie(&mut self, digest: Digest, trie: Trie) -> Result<(), Self::Error> {
        self.0.insert(digest, trie.as_bytes().to_owned());
        Ok(())
    }
}

impl TrieTransactional for InMemoryStore {
    type ErrorCreatingTransaction = Infallible;
    type Transaction = Self;

    fn transaction<F, A, E>(
        &mut self,
        mut f: F,
    ) -> Result<A, TransactionError<Self::ErrorCreatingTransaction, E>>
    where
        E: std::error::Error,
        F: FnMut(&mut Self::Transaction) -> Result<A, E>,
    {
        f(self).map_err(TransactionError::Abort)
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

    // fn bulk_trie_download(
    //   root: Digest,
    //   prefixes: Vec<Vec<u8>>,
    //   missing_descendants: Vec<Digest>,
    //   bloom_filter: BloomFilter) -> Result<Vec<WireTrie>, DigestNotUnderPrefix>
    // TODO: Read with proof
    // TODO: Bulk trie retrieve
}
