mod fast_sync;
mod garbage_collect;

pub mod backends;
mod iterators;
pub mod updater;

pub use crate::store::{
    backends::in_memory::InMemoryStore,
    iterators::{
        missing_trie_descendants::{
            MissingTrieDescendantsIterator, MissingTrieDescendantsIteratorError,
        },
        trie_leaves_under_prefix::{
            TrieLeavesUnderPrefixIterator, TrieLeavesUnderPrefixIteratorError,
        },
    },
};
use crate::{wire_trie::Trie, Digest};

// TODO: wrap rocksdb - talk to Dan

// TODO: struct Ref(u64)
// TODO struct Store { roots: HashMap<Digest, Ref>, tries: HashMap<Ref, Vec<u8>> }

pub trait TrieReader: Sized {
    type Error: std::error::Error;
    fn get_trie(&self, digest: &Digest) -> Result<Option<Trie>, Self::Error>;

    fn leaves_under_prefix(
        &self,
        root: Digest,
        prefix: Vec<u8>,
    ) -> TrieLeavesUnderPrefixIterator<Self> {
        TrieLeavesUnderPrefixIterator::new(self, root, prefix)
    }

    fn find_missing_trie_descendants(
        &self,
        digest: Digest,
    ) -> MissingTrieDescendantsIterator<Self> {
        MissingTrieDescendantsIterator::new(self, digest)
    }
}

pub trait TrieWriter {
    type Error: std::error::Error;
    fn put_trie(&mut self, digest: Digest, trie: Trie) -> Result<(), Self::Error>;
}

#[derive(thiserror::Error, Debug)]
pub enum TransactionError<E1, E2> {
    #[error("{0}")]
    ErrorCreatingTransaction(E1),
    #[error("{0}")]
    Abort(E2),
}

pub trait TrieTransactional {
    type ErrorCreatingTransaction: std::error::Error;
    type Transaction: TrieWriter;

    fn transaction<F, A, E>(
        &mut self,
        f: F,
    ) -> Result<A, TransactionError<Self::ErrorCreatingTransaction, E>>
    where
        E: std::error::Error,
        F: FnMut(&mut Self::Transaction) -> Result<A, E>;
}
