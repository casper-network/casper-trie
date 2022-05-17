use crate::store::{TransactionError, TrieTransactional, TrieWriter};
use crate::{
    store::TrieReader,
    wire_trie::{TrieLeafOrBranch, TrieReadError, TrieTag, EMPTY_TRIE_ROOT},
    Digest, Trie, DIGEST_LENGTH,
};

// This is an intermediate structure that is created by the Updater
pub(crate) struct OwnedTrie(Vec<u8>);

/// Keys can be zero in length, but we want to represent every possible key length with a u8.
/// The maximum u8 is 255.
pub const MAX_KEY_BYTES_LEN: u8 = 255;

impl OwnedTrie {
    fn as_trie(&self) -> Trie {
        Trie::new(&self.0)
    }

    pub(crate) fn trie_hash(&self) -> Digest {
        self.as_trie().trie_hash()
    }

    pub(crate) fn get_nth_digest(&self, n: u8) -> Result<TrieLeafOrBranch, TrieReadError> {
        self.as_trie().get_nth_digest(n)
    }

    pub(crate) fn version_byte_and_envelope_hash(&self) -> blake3::Hash {
        self.as_trie().version_byte_and_envelope_hash()
    }
}

impl AsRef<[u8]> for OwnedTrie {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<OwnedTrie> for Vec<u8> {
    fn from(owned_trie: OwnedTrie) -> Self {
        owned_trie.0
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct OwnedLeaf(Vec<u8>);

#[derive(thiserror::Error, Debug)]
#[error("Key must have at most 255 bytes. Byte count: {key_byte_count}, key: {key:?}")]
pub struct KeyMustHaveAtMost255Bytes {
    key: Vec<u8>,
    key_byte_count: usize,
}

impl OwnedLeaf {
    pub(crate) fn new(key: &[u8], value: &[u8]) -> Result<Self, KeyMustHaveAtMost255Bytes> {
        let key_byte_count = key.len();
        if key_byte_count > MAX_KEY_BYTES_LEN as usize {
            return Err(KeyMustHaveAtMost255Bytes {
                key_byte_count,
                key: key.to_owned(),
            });
        }

        let mut data = Vec::with_capacity(1 + key_byte_count + value.len());
        data.push(key_byte_count as u8);
        data.extend(key);
        data.extend(value);

        Ok(OwnedLeaf(data))
    }

    pub(crate) fn key(&self) -> &[u8] {
        let data = &self.0;
        &data[1..1 + data[0] as usize]
    }
}

impl From<OwnedLeaf> for OwnedTrie {
    fn from(leaf: OwnedLeaf) -> Self {
        let mut data = Vec::with_capacity(1 + leaf.0.len());
        data.push(TrieTag::Leaf as u8);
        data.extend(leaf.0);
        OwnedTrie(data)
    }
}

#[derive(Debug, Eq, PartialEq)]
// TODO: Move into separate module
pub(crate) enum UpdatingTrie {
    /// Represents either an empty root hash (ie, [0u8; 32]) or a missing branch in a node.
    Empty,
    /// A digest referring to some element in the trie-store.
    Digest(Box<Digest>),
    // TODO: Introduce ref variant
    /// A leaf consisting of a key and value represented as bytes.
    Leaf(Box<OwnedLeaf>),
    /// A node with an affix and branches.
    Node(Box<Node>),
}

#[derive(Debug, Eq, PartialEq)]
// TODO: Move into separate module
// TODO: Make ARTful
// TODO: Make more compact so we can use NODE4
// Note that a Node3 fits in a cache line (rather than a Node4)
// Change to Option<Box<UpdatingTrie>>
// Otherwise follow the paper with Node16 & Node48
pub(crate) struct Node {
    affix: Vec<u8>,
    branch_count: u8,
    branches: [UpdatingTrie; 256],
}

impl Node {
    pub(crate) fn new_empty(affix: Vec<u8>) -> Node {
        Node {
            affix,
            branch_count: 0,
            branches: empty_branches(),
        }
    }

    // WARNING: This method *not* suitable for a public interface.
    //
    // Return a mutable reference to a branch corresponding to `idx`.
    // Increment the branch counter if the branch is `Empty`.
    //
    // Note: This interface does not preserve the invariant:
    //
    // branch_count = branches.filter(|b| !matches!(b, UpdatingTrie::Empty)).count()
    //
    // It is up to the caller to ensure this invariant holds.
    // This method is exposed to enable inserting elements into a recursive UpdatingTrie structure.
    pub(crate) fn new_branch_at_idx(&mut self, idx: u8) -> &mut UpdatingTrie {
        let branch = &mut self.branches[idx as usize];
        if UpdatingTrie::Empty == *branch {
            self.branch_count += 1;
        }
        branch
    }

    pub(crate) fn swap_new_branch_at_idx(
        &mut self,
        idx: u8,
        updating_trie_to_insert: &mut UpdatingTrie,
    ) {
        std::mem::swap(self.new_branch_at_idx(idx), updating_trie_to_insert);
    }

    pub(crate) fn swap_branch_at_idx(
        &mut self,
        idx: u8,
        updating_trie_to_insert: &mut UpdatingTrie,
    ) {
        std::mem::swap(&mut self.branches[idx as usize], updating_trie_to_insert);
    }

    pub(crate) fn iter_mut_non_flat_branches_from_starting_index(
        &mut self,
        starting_index: u8,
    ) -> impl Iterator<Item = (u8, &mut UpdatingTrie)> {
        self.branches[starting_index as usize..]
            .iter_mut()
            .enumerate()
            .filter_map(move |(trie_idx, updating_trie)| {
                if matches!(updating_trie, UpdatingTrie::Empty | UpdatingTrie::Digest(_)) {
                    None
                } else {
                    Some((starting_index + trie_idx as u8, updating_trie))
                }
            })
    }

    pub(crate) fn affix(&self) -> &[u8] {
        &self.affix
    }
}

impl UpdatingTrie {
    pub(crate) fn digest(digest: [u8; DIGEST_LENGTH]) -> Self {
        UpdatingTrie::Digest(Box::new(digest))
    }

    pub(crate) fn leaf(leaf: OwnedLeaf) -> Self {
        UpdatingTrie::Leaf(Box::new(leaf))
    }

    pub(crate) fn node(node: Node) -> Self {
        UpdatingTrie::Node(Box::new(node))
    }
}

fn empty_branches() -> [UpdatingTrie; 256] {
    use self::UpdatingTrie::Empty;
    [
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
        Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty, Empty,
    ]
}

#[derive(thiserror::Error, Debug)]
pub enum TrieToUpdatingTrieConversionError {
    #[error("Invalid trie tag code")]
    InvalidTrieTagCode,

    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}

impl TryFrom<Trie<'_>> for UpdatingTrie {
    type Error = TrieToUpdatingTrieConversionError;

    fn try_from(trie: Trie) -> Result<Self, Self::Error> {
        // The 3 highest significant bits are the tag code, the lower 5 bits are the branch count.
        let tag = trie.tag();
        if tag == TrieTag::Leaf {
            return Ok(UpdatingTrie::leaf(OwnedLeaf(trie.as_bytes()[1..].to_vec())));
        }

        let mut branches = empty_branches();
        let mut branch_count = 0;
        for (branch_index, branch) in trie.iter_branches() {
            branches[branch_index? as usize] = UpdatingTrie::digest(*branch?);
            branch_count += 1;
        }

        Ok(UpdatingTrie::node(Node {
            affix: trie.key_or_affix().to_vec(),
            branch_count,
            branches,
        }))
    }
}

impl TryFrom<&OwnedTrie> for UpdatingTrie {
    type Error = TrieToUpdatingTrieConversionError;

    fn try_from(owned_trie: &OwnedTrie) -> Result<Self, Self::Error> {
        UpdatingTrie::try_from(Trie::new(&owned_trie.0))
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Node is not flat. It must only have empty or digest branches. Bad branch index: {bad_branch_index}")]
pub struct NodeMustBeFlatError {
    pub(crate) bad_branch_index: usize,
}

impl TryFrom<&Node> for OwnedTrie {
    type Error = NodeMustBeFlatError;

    fn try_from(node: &Node) -> Result<Self, Self::Error> {
        debug_assert_eq!(
            node.branch_count as usize,
            node.branches
                .iter()
                .filter(|branch| !matches!(branch, UpdatingTrie::Empty))
                .count(),
            "Node has incorrect branch count: {:?}",
            node
        );

        let Node {
            affix,
            branch_count,
            branches,
        } = node;

        let branch_count = *branch_count as usize;
        if branch_count < 32 {
            let mut data = Vec::<u8>::with_capacity(
                1                     // tag || number of branches byte
                    + 1                   // affix length
                    + affix.len()         // affix
                    + branch_count        // branches search index
                    + 32 * branch_count, // hashes of each branch
            );
            data.push((TrieTag::Node31 as u8) << 5 | branch_count as u8);
            data.push(affix.len() as u8);
            data.extend(affix);
            let mut branch_bytes = Vec::<u8>::with_capacity(32 * branch_count);
            for (idx, updating_trie) in branches.iter().enumerate() {
                match updating_trie {
                    UpdatingTrie::Empty => continue,
                    UpdatingTrie::Node(_) | UpdatingTrie::Leaf(_) => {
                        return Err(NodeMustBeFlatError {
                            bad_branch_index: idx,
                        })
                    }
                    UpdatingTrie::Digest(digest) => {
                        data.push(idx as u8);
                        branch_bytes.extend(**digest);
                    }
                }
            }
            data.extend(branch_bytes);
            Ok(OwnedTrie(data))
        } else {
            let mut data = Vec::<u8>::with_capacity(
                1                    // tag byte
                    + 1                  // affix length
                    + affix.len()        // affix
                    + 32                 // branches bit-array
                    + 32 * branch_count, // hashes of each branch
            );
            data.push((TrieTag::Node256 as u8) << 5);
            data.push(affix.len() as u8);
            data.extend(affix);
            let mut branch_bytes: Vec<u8> = vec![];
            let mut index_chunk = 0u64;
            let mut branches = branches.iter().enumerate();
            match branches.next() {
                Some((0, UpdatingTrie::Empty)) => (),
                Some((0, UpdatingTrie::Digest(digest))) => {
                    index_chunk = 1;
                    branch_bytes.extend(**digest);
                }
                Some((0, UpdatingTrie::Node(_) | UpdatingTrie::Leaf(_))) => {
                    return Err(NodeMustBeFlatError {
                        bad_branch_index: 0,
                    });
                }
                _ => unreachable!(), // there must be >= 32 branches and the index must be 0
            }
            for (idx, updating_trie) in branches {
                let rem = idx % 64;
                if rem == 0 {
                    data.extend(index_chunk.to_le_bytes());
                    index_chunk = 0;
                }
                match updating_trie {
                    UpdatingTrie::Empty => continue,
                    UpdatingTrie::Digest(digest) => {
                        index_chunk |= 1 << rem;
                        branch_bytes.extend(**digest)
                    }
                    UpdatingTrie::Node(_) | UpdatingTrie::Leaf(_) => {
                        return Err(NodeMustBeFlatError {
                            bad_branch_index: idx,
                        });
                    }
                }
            }
            data.extend(index_chunk.to_le_bytes());
            data.extend(branch_bytes);
            Ok(OwnedTrie(data))
        }
    }
}

#[derive(Debug)]
pub struct Updater<'a, S> {
    current_state: UpdatingTrie,
    store: &'a mut S,
}

#[derive(thiserror::Error, Debug)]
pub enum UpdaterPutError<S>
where
    S: TrieReader,
{
    #[error("Digest not found: {0:?}")]
    DigestNotFound(Box<Digest>),

    #[error(transparent)]
    TrieToUpdatingTrieConversionError(#[from] TrieToUpdatingTrieConversionError),

    #[error("Tried to insert key that is a prefix of another.  Key to be inserted: {bad_key:?}")]
    TriedToInsertKeyThatIsPrefixOfAnother { bad_key: Vec<u8> },

    #[error(transparent)]
    KeyMustHaveAtMost255Bytes(#[from] KeyMustHaveAtMost255Bytes),

    #[error(transparent)]
    TrieStoreError(<S as TrieReader>::Error),
}

impl<'a, S> Updater<'a, S> {
    pub fn new(store: &'a mut S, state_root: Digest) -> Updater<'a, S> {
        let current_state = if state_root == EMPTY_TRIE_ROOT {
            UpdatingTrie::Empty
        } else {
            UpdatingTrie::digest(state_root)
        };
        Updater {
            current_state,
            store,
        }
    }

    // TODO: delete

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), UpdaterPutError<S>>
    where
        S: TrieReader,
    {
        let new_leaf = Box::new(OwnedLeaf::new(key, value)?);
        let mut key_bytes_traversed_count: usize = 0;
        let mut traversed_state = &mut self.current_state;
        loop {
            match traversed_state {
                UpdatingTrie::Empty => {
                    // If we have traversed to an empty trie, we can break and swap the new leaf in.
                    break;
                }
                UpdatingTrie::Digest(digest) => {
                    // If we have hit a digest, load the trie from the store and loop again.
                    let mut updating_trie = match self
                        .store
                        .get_trie(&**digest)
                        .map_err(UpdaterPutError::TrieStoreError)?
                    {
                        None => {
                            return Err(UpdaterPutError::DigestNotFound(digest.clone()));
                        }
                        Some(trie) => UpdatingTrie::try_from(trie)?,
                    };
                    std::mem::swap(traversed_state, &mut updating_trie);
                    continue;
                }
                UpdatingTrie::Leaf(leaf) => {
                    // If we have hit a leaf, get the common affix.
                    let affix_end_position = key_bytes_traversed_count
                        + leaf.key()[key_bytes_traversed_count..]
                            .iter()
                            .zip(new_leaf.key()[key_bytes_traversed_count..].iter())
                            .take_while(|(byte1, byte2)| byte1 == byte2)
                            .count();

                    // If this is all of the key bytes, then the key's value has been updated.
                    // We can break and swap in the new value for the old.
                    if affix_end_position == new_leaf.key().len()
                        || affix_end_position == leaf.key().len()
                    {
                        if new_leaf.key().len() != leaf.key().len() {
                            return Err(UpdaterPutError::TriedToInsertKeyThatIsPrefixOfAnother {
                                bad_key: new_leaf.key().to_vec(),
                            });
                        }
                        break;
                    }

                    // Create a new node with the common affix
                    let mut new_node = Node::new_empty(
                        leaf.key()[key_bytes_traversed_count..affix_end_position].to_vec(),
                    );
                    // Put in a branch for the leaf we have traversed to.
                    // The traversed state will now point to an empty trie.
                    new_node
                        .swap_new_branch_at_idx(leaf.key()[affix_end_position], traversed_state);
                    // Update the key bytes traversed count
                    key_bytes_traversed_count = affix_end_position;
                    // Swap in the new node so where we traversed to points to it.
                    std::mem::swap(traversed_state, &mut UpdatingTrie::node(new_node));
                }
                UpdatingTrie::Node(node) => {
                    // Compute the new affix position
                    let common_affix_length = node
                        .affix()
                        .iter()
                        .zip(new_leaf.key()[key_bytes_traversed_count..].iter())
                        .take_while(|(byte1, byte2)| byte1 == byte2)
                        .count();

                    if common_affix_length + key_bytes_traversed_count >= new_leaf.key().len() {
                        return Err(UpdaterPutError::TriedToInsertKeyThatIsPrefixOfAnother {
                            bad_key: new_leaf.key().to_vec(),
                        });
                    }
                    key_bytes_traversed_count += common_affix_length;

                    if common_affix_length != node.affix().len() {
                        // The new leaf shares part of an affix with the node we've traversed to.
                        // Make the node we have traversed to a child of a new node.
                        // It will be a sibling branch of where we put our leaf.
                        let mut new_node =
                            Node::new_empty(node.affix()[..common_affix_length].to_vec());
                        let index_of_new_child_branch = node.affix()[common_affix_length];
                        node.affix = node.affix()[common_affix_length + 1..].to_vec();
                        new_node.swap_new_branch_at_idx(index_of_new_child_branch, traversed_state);
                        std::mem::swap(traversed_state, &mut UpdatingTrie::node(new_node))
                    }
                }
            }

            // If the traversed state is a node, go to the branch corresponding to how many bytes
            // we have traversed and updated the traversed state.
            if let UpdatingTrie::Node(new_node) = traversed_state {
                traversed_state =
                    new_node.new_branch_at_idx(new_leaf.key()[key_bytes_traversed_count]);
                key_bytes_traversed_count += 1;
            }
        }
        let mut new_trie = UpdatingTrie::Leaf(new_leaf);
        std::mem::swap(traversed_state, &mut new_trie);
        Ok(())
    }

    // TODO: look into hadoop-style reducers here
    /// Writes the state of the updater to the store, computing the Merkle tree updates along the
    /// way.
    pub fn commit(
        self,
    ) -> Result<
        Digest,
        TransactionError<
            <S as TrieTransactional>::ErrorCreatingTransaction,
            <<S as TrieTransactional>::Transaction as TrieWriter>::Error,
        >,
    >
    where
        S: TrieTransactional,
    {
        let mut current_state = self.current_state;

        self.store.transaction(move |trie_writer| {
            // Get ownership of the current state
            let current_state = {
                let mut my_current_state = UpdatingTrie::Empty;
                std::mem::swap(&mut my_current_state, &mut current_state);
                my_current_state
            };
            let starting_node = match current_state {
                UpdatingTrie::Empty => {
                    return Ok([0; 32]);
                }
                UpdatingTrie::Digest(digest) => {
                    return Ok(*digest);
                }
                UpdatingTrie::Leaf(leaf) => {
                    let owned_trie = OwnedTrie::from(*leaf);
                    let digest = owned_trie.trie_hash();
                    trie_writer.put_trie(digest, owned_trie.as_trie())?;
                    return Ok(digest);
                }
                UpdatingTrie::Node(node) => node,
            };

            struct NodeStackElement {
                resume_position: u8,
                node: Box<Node>,
            }

            let mut node_stack: Vec<NodeStackElement> = vec![NodeStackElement {
                resume_position: 0,
                node: starting_node,
            }];
            let mut digest_to_be_slotted_into_node_at_top_of_stack: Option<Digest> = None;
            while let Some(NodeStackElement {
                mut resume_position,
                mut node,
            }) = node_stack.pop()
            {
                if let Some(digest) = digest_to_be_slotted_into_node_at_top_of_stack {
                    node.swap_branch_at_idx(resume_position, &mut UpdatingTrie::digest(digest));
                    digest_to_be_slotted_into_node_at_top_of_stack = None;
                    resume_position = resume_position.saturating_add(1)
                };

                let mut maybe_new_node_to_push = UpdatingTrie::Empty;
                for (idx, branch) in
                    node.iter_mut_non_flat_branches_from_starting_index(resume_position)
                {
                    match branch {
                        UpdatingTrie::Empty | UpdatingTrie::Digest(_) => {
                            unreachable!()
                        }
                        UpdatingTrie::Leaf(_) => {
                            let mut leaf = UpdatingTrie::Empty;
                            std::mem::swap(branch, &mut leaf);
                            if let UpdatingTrie::Leaf(leaf) = leaf {
                                let owned_trie = OwnedTrie::from(*leaf);
                                let digest = owned_trie.trie_hash();
                                trie_writer.put_trie(digest, owned_trie.as_trie())?;
                                std::mem::swap(branch, &mut UpdatingTrie::digest(digest));
                            }
                        }
                        UpdatingTrie::Node(_) => {
                            resume_position = idx;
                            std::mem::swap(branch, &mut maybe_new_node_to_push);
                            break;
                        }
                    }
                }
                if let UpdatingTrie::Node(new_node_to_push) = maybe_new_node_to_push {
                    node_stack.push(NodeStackElement {
                        resume_position,
                        node,
                    });
                    node_stack.push(NodeStackElement {
                        resume_position: 0,
                        node: new_node_to_push,
                    });
                } else {
                    let owned_trie = OwnedTrie::try_from(&*node).expect("node must be flat");
                    let digest = owned_trie.trie_hash();
                    trie_writer.put_trie(digest, owned_trie.as_trie())?;
                    digest_to_be_slotted_into_node_at_top_of_stack = Some(digest);
                }
            }
            // We can expect because it's unreachable to get here with the digest as `None`
            Ok(digest_to_be_slotted_into_node_at_top_of_stack
                .expect("Must have inserted top node into trie store"))
        })
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Key must be greater than 0 bytes and less than 256 bytes. Key length: {key_length}")]
struct InvalidKeyLength {
    key_length: usize,
}

#[cfg(test)]
mod tests {
    use crate::{
        store::{
            backends::in_memory::InMemoryStore,
            updater::{Node, NodeMustBeFlatError, OwnedLeaf, OwnedTrie, Updater, UpdatingTrie},
        },
        wire_trie::{TrieLeafOrBranch, EMPTY_TRIE_ROOT},
        Digest,
    };

    fn node_with_n_branches(branch_count: u8, offset: u8, spacing: u8) -> Node {
        let mut node = Node::new_empty(vec![0, 1, 2]);
        if spacing == 0 {
            for branch_idx in offset..offset + branch_count {
                node.swap_new_branch_at_idx(
                    branch_idx,
                    &mut UpdatingTrie::digest([(branch_idx % 8) as u8; 32]),
                );
            }
        } else {
            for branch_idx in (offset..offset + spacing * branch_count).step_by(spacing as usize) {
                node.swap_new_branch_at_idx(
                    branch_idx,
                    &mut UpdatingTrie::digest([(branch_idx % 8) as u8; 32]),
                );
            }
        };
        node
    }

    fn try_trie_hash(node: &Node) -> Result<Digest, NodeMustBeFlatError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(
            OwnedTrie::try_from(node)?
                .version_byte_and_envelope_hash()
                .as_bytes(),
        );
        for (idx, updating_trie) in node.branches.iter().enumerate() {
            match updating_trie {
                UpdatingTrie::Empty => continue,
                UpdatingTrie::Digest(digest) => {
                    hasher.update(&**digest);
                }
                UpdatingTrie::Node(_) | UpdatingTrie::Leaf(_) => {
                    return Err(NodeMustBeFlatError {
                        bad_branch_index: idx,
                    })
                }
            }
        }
        Ok(hasher.finalize().into())
    }

    #[test]
    fn node_with_n_branches_round_trip_with_offset() {
        for branch_count in 1..128 {
            for offset in 0..128 {
                let node = node_with_n_branches(branch_count, offset, 0);
                let owned_trie = OwnedTrie::try_from(&node).expect("should convert to trie bytes");
                let expected = UpdatingTrie::node(node_with_n_branches(branch_count, offset, 0));
                let parsed =
                    UpdatingTrie::try_from(&owned_trie).expect("should convert to UpdatingTrie");
                assert_eq!(expected, parsed)
            }
        }
    }

    #[test]
    fn node_with_n_branches_round_trip() {
        for branch_count in 1..=255 {
            let node = node_with_n_branches(branch_count, 0, 0);
            let owned_trie = OwnedTrie::try_from(&node).expect("should convert to trie bytes");
            let expected = UpdatingTrie::node(node_with_n_branches(branch_count, 0, 0));
            let parsed =
                UpdatingTrie::try_from(&owned_trie).expect("should convert to UpdatingTrie");
            assert_eq!(expected, parsed)
        }
    }

    #[test]
    fn node_with_n_branches_serialize_and_get_digests_with_offset() {
        for branch_count in 1..40 {
            for offset in 0..10 {
                let owned_trie =
                    OwnedTrie::try_from(&node_with_n_branches(branch_count, offset, 3))
                        .expect("should convert to trie bytes");
                let mut idx = 0;
                for branch in node_with_n_branches(branch_count, offset, 3).branches {
                    let expected_digest = match branch {
                        UpdatingTrie::Digest(digest) => *digest,
                        UpdatingTrie::Empty => continue,
                        unexpected_branch => panic!("Unexpected branch: {:?}", unexpected_branch),
                    };
                    let retrieved_digest = match owned_trie
                        .get_nth_digest(idx as u8)
                        .expect("Should read digest")
                    {
                        TrieLeafOrBranch::Branch(digest) => digest,
                        unexpected_trie_read_output => panic!(
                            "Unexpected trie read output with branches {} and offset {} (idx = {}): {:?}",
                            branch_count, offset, idx, unexpected_trie_read_output
                        ),
                    };
                    assert_eq!(expected_digest, *retrieved_digest);
                    idx += 1;
                }
            }
        }
    }

    #[test]
    fn node_with_n_branches_trie_hash_with_offset() {
        for branch_count in 1..128 {
            for offset in 0..128 {
                let node = node_with_n_branches(branch_count, offset, 0);
                let node_hash = try_trie_hash(&node).expect("could not hash UpdatingTrie");
                let trie_hash = OwnedTrie::try_from(&node)
                    .expect("should convert to trie bytes")
                    .trie_hash();
                assert_eq!(
                    node_hash, trie_hash,
                    "hashes were not the same, branch count {} offset {}",
                    branch_count, offset
                )
            }
        }
    }

    #[test]
    fn updater_put_one() {
        let mut store = InMemoryStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let key = vec![0, 1, 2, 3];
        let value = vec![0, 1, 2, 3];
        updater.put(&key, &value).expect("Could not put");
        assert_eq!(
            updater.current_state,
            UpdatingTrie::leaf(OwnedLeaf::new(&key, &value).expect("Could not make leaf"))
        )
    }

    #[test]
    fn updater_put_same_key_twice() {
        let mut store = InMemoryStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let key = vec![0, 1, 2, 3];
        let value1 = vec![0, 1, 2, 3];
        let value2 = vec![0, 1, 2, 3, 4];
        updater.put(&key, &value1).expect("Could not put");
        updater.put(&key, &value2).expect("Could not put");
        assert_eq!(
            updater.current_state,
            UpdatingTrie::leaf(OwnedLeaf::new(&key, &value2).expect("Could not make leaf"))
        )
    }

    #[test]
    fn updater_put_different_keys_with_different_final_byte() {
        let mut store = InMemoryStore::new();
        let mut updater = Updater::new(&mut store, EMPTY_TRIE_ROOT);
        let key1 = vec![0, 1, 2, 3];
        let key2 = vec![0, 1, 2, 4];
        let value = vec![0, 1, 2, 3];
        updater.put(&key1, &value).expect("Could not put");
        updater.put(&key2, &value).expect("Could not put");
        assert!(
            matches!(updater.current_state, UpdatingTrie::Node(_)),
            "Current state should be a node: {:?}",
            updater.current_state
        )
    }
}
