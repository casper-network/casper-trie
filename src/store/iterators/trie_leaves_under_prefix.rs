use crate::{
    store::TrieReader,
    wire_trie::{Leaf, TrieLeafOrBranch, TrieReadError, TrieTag},
    Digest, EMPTY_TRIE_ROOT,
};

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
