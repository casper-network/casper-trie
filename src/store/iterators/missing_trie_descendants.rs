use crate::{
    store::TrieReader,
    wire_trie::{BranchIterator, TrieReadError},
    Digest, EMPTY_TRIE_ROOT,
};

#[derive(thiserror::Error, Debug)]
pub enum MissingTrieDescendantsIteratorError<S>
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
    type Item = Result<Digest, MissingTrieDescendantsIteratorError<S>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(initial_trie_digest) = self.maybe_initial_trie_digest.take() {
            if initial_trie_digest == EMPTY_TRIE_ROOT {
                return None;
            }
            let initial_trie = match self.store.get_trie(&initial_trie_digest).transpose() {
                Some(Ok(initial_trie)) => initial_trie,
                Some(Err(err)) => {
                    return Some(Err(MissingTrieDescendantsIteratorError::TrieStoreError(
                        err,
                    )));
                }
                None => {
                    return Some(Ok(initial_trie_digest));
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
                    return Some(Err(MissingTrieDescendantsIteratorError::TrieStoreError(
                        err,
                    )));
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
