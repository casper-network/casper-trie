mod fast_sync;
mod garbage_collect;

pub mod backends;
pub mod updater;

pub use crate::store::backends::in_memory::InMemoryStore;
use crate::wire_trie::BranchIterator;
use crate::{
    wire_trie::{Leaf, Trie, TrieLeafOrBranch, TrieReadError, TrieTag, EMPTY_TRIE_ROOT},
    Digest,
};

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

#[derive(thiserror::Error, Debug)]
pub enum TrieLeavesUnderPrefixIteratorError<S>
where
    S: TrieReader,
{
    #[error("Digest not found: {0:?}")]
    DigestNotFound(Box<Digest>),

    #[error(transparent)]
    TrieStoreError(<S as TrieReader>::Error),

    #[error(transparent)]
    TrieReadError(#[from] TrieReadError),
}

pub struct TrieLeavesUnderPrefixIterator<'a, S> {
    root: Digest,
    store: &'a S,
    prefix: Vec<u8>,
    initialized: bool,
    node_stack: Vec<(Digest, u8)>,
}

impl<'a, S> TrieLeavesUnderPrefixIterator<'a, S> {
    pub fn new(store: &'a S, root: Digest, prefix: Vec<u8>) -> Self {
        Self {
            root,
            store,
            prefix,
            initialized: false,
            node_stack: Vec::new(),
        }
    }
}

impl<'a, S> Iterator for TrieLeavesUnderPrefixIterator<'a, S>
where
    S: TrieReader,
{
    type Item = Result<Leaf<'a>, TrieLeavesUnderPrefixIteratorError<S>>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.initialized {
            if self.root == EMPTY_TRIE_ROOT {
                self.initialized = true;
                return None;
            }

            let mut current_lookup_digest = self.root;
            let mut prefix_bytes_read: u8 = 0;
            loop {
                let trie = match self.store.get_trie(&current_lookup_digest) {
                    Ok(Some(trie)) => trie,
                    Ok(None) => {
                        // Could not look up digest. The digest may not exist or trie-store may be
                        // corrupted. Stop iterating.
                        self.initialized = true;
                        return Some(Err(TrieLeavesUnderPrefixIteratorError::DigestNotFound(
                            Box::new(current_lookup_digest),
                        )));
                    }
                    Err(err) => {
                        self.initialized = true;
                        return Some(Err(TrieLeavesUnderPrefixIteratorError::TrieStoreError(err)));
                    }
                };

                if trie.tag() == TrieTag::Leaf {
                    self.initialized = true;
                    if trie.key_or_affix().starts_with(&self.prefix) {
                        return Some(Ok(Leaf::new(trie)));
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
                    trie.read_using_search_key(&self.prefix, &mut prefix_bytes_read)
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
                Ok(Some(trie)) => trie,
                Ok(None) => {
                    self.node_stack.clear();
                    return Some(Err(TrieLeavesUnderPrefixIteratorError::DigestNotFound(
                        Box::new(node_digest),
                    )));
                }
                Err(err) => {
                    self.node_stack.clear();
                    return Some(Err(TrieLeavesUnderPrefixIteratorError::TrieStoreError(err)));
                }
            };
            match trie.get_nth_digest(branch_idx) {
                Ok(TrieLeafOrBranch::Leaf(leaf)) => {
                    return Some(Ok(leaf));
                }
                Ok(TrieLeafOrBranch::Branch(new_digest)) => {
                    self.node_stack.push((node_digest, branch_idx + 1));
                    self.node_stack.push((*new_digest, 0));
                }
                Ok(TrieLeafOrBranch::IndexOutOfRange) => continue,
                Ok(TrieLeafOrBranch::KeyNotFound) => {
                    unreachable!("get_nth_digest should never return KeyNotFound")
                }
                Err(err) => {
                    self.node_stack.clear();
                    return Some(Err(err.into()));
                }
            }
        }
        None
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MissingTrieIteratorError<S>
where
    S: TrieReader,
{
    #[error(transparent)]
    TrieStoreError(<S as TrieReader>::Error),

    #[error(transparent)]
    TrieReadError(#[from] TrieReadError),
}

pub struct MissingTrieDescendantsIterator<'a, S> {
    store: &'a S,
    maybe_initial_trie_digest: Option<Digest>,
    trie_branches_being_visited: Vec<BranchIterator<'a>>,
}

impl<'a, S> MissingTrieDescendantsIterator<'a, S> {
    pub fn new(store: &'a S, initial_trie_digest: Digest) -> Self {
        Self {
            store,
            maybe_initial_trie_digest: Some(initial_trie_digest),
            trie_branches_being_visited: Vec::new(),
        }
    }
}

impl<'a, S> Iterator for MissingTrieDescendantsIterator<'a, S>
where
    S: TrieReader,
{
    type Item = Result<Digest, MissingTrieIteratorError<S>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(initial_trie_digest) = self.maybe_initial_trie_digest.take() {
            let initial_trie = match self.store.get_trie(&initial_trie_digest).transpose() {
                Some(Ok(initial_trie)) => initial_trie,
                Some(Err(err)) => {
                    return Some(Err(MissingTrieIteratorError::TrieStoreError(err)));
                }
                None => {
                    if initial_trie_digest == EMPTY_TRIE_ROOT {
                        return None;
                    } else {
                        return Some(Ok(initial_trie_digest));
                    }
                }
            };
            self.trie_branches_being_visited
                .push(initial_trie.iter_branch_digests());
        }
        loop {
            let branch_iter = self.trie_branches_being_visited.last_mut()?;
            let branch_digest = match branch_iter.next() {
                Some(Ok(branch_digest)) => branch_digest,
                Some(Err(err)) => {
                    return Some(Err(err.into()));
                }
                None => {
                    self.trie_branches_being_visited.pop();
                    continue;
                }
            };
            let trie = match self.store.get_trie(branch_digest).transpose() {
                Some(Ok(trie)) => trie,
                Some(Err(err)) => {
                    return Some(Err(MissingTrieIteratorError::TrieStoreError(err)));
                }
                None => {
                    return Some(Ok(*branch_digest));
                }
            };
            self.trie_branches_being_visited
                .push(trie.iter_branch_digests());
        }
    }
}
