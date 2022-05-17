//! A wire-format for a Merkle Patricia trie. This is a new-type around raw bytes. The raw bytes
//! have two components.
//!
//! The two components are:
//!
//! 1. An _envelope_
//! 2. A _value_ or list of cryptographic hashes representing branches.
//!
//! The envelope has the following byte structure:
//!
//! - Byte 0:
//!   - A tag encoded as the most significant 3 bits.
//!     - 0: The trie is a leaf.
//!     - 1: The trie is a radix-31 node.
//!     - 2: The trie is a radix-256 node.
//!   - A branch count encoded as the least significant 5 bits when this is a Node31
//! - Byte 1: Key or affix length.
//! - Bytes 2 to at most 256+2: The key or affix. These bytes are for a key if the highest three
//!   bits in byte 1 were LEAF_TAG (ie, 0). Otherwise it is an affix, because the trie is a node
//!   with branches.
//! - Additional bytes: Depends on the tag
//!   - Leaf: these are the values of the leaf, represented as a blob of bytes with no prefixed
//!     length.
//!   - Node31: this sort of node has
//!     - Search index bytes, with length indicated by the bottom 5 bits of the first byte. These
//!       bytes are always in order so we can use binary searches.
//!     - A list of hashes. Each hash is DIGEST_LENGTH (ie, 32) bytes long. The length of this list
//!       is the same as the bottom 5 bits of the first byte.
//!   - Node256: this sort of node has
//!     - A bitvector of 32 bytes (256 bits)
//!     - A list of hashes.
//!
//! Nodes cannot have 0 branches or just 1 branch.

use std::{array::TryFromSliceError, iter::Map, slice::Chunks};

pub const DIGEST_LENGTH: usize = 32;
pub type Digest = [u8; DIGEST_LENGTH];
pub const EMPTY_TRIE_ROOT: [u8; DIGEST_LENGTH] = [0u8; DIGEST_LENGTH];

const VERSION: u8 = 0;

#[derive(PartialEq, Eq)]
#[repr(u8)]
pub enum TrieTag {
    Leaf = 0,
    Node31 = 1,
    Node256 = 2,
    Unknown = 255,
}

pub struct Trie<'a>(&'a [u8]);

pub type TrieReadError = std::array::TryFromSliceError;

#[derive(Debug, Clone)]
pub struct Leaf<'a>(&'a [u8]);

impl<'a> Leaf<'a> {
    pub(crate) fn new(wire_trie_ref: Trie) -> Leaf {
        let Trie(raw_bytes) = wire_trie_ref;
        // Throw away the leading byte and leave only the key length and data
        Leaf(&raw_bytes[1..])
    }

    pub(crate) fn key(&self) -> &[u8] {
        let data = self.0;
        &data[1..1 + data[0] as usize]
    }

    pub(crate) fn value(&self) -> &[u8] {
        let data = self.0;
        &data[1 + data[0] as usize..]
    }
}

#[derive(Debug)]
pub(crate) enum TrieLeafOrBranch<'a> {
    Leaf(Leaf<'a>),
    Branch(&'a Digest),
    KeyNotFound,
    IndexOutOfRange,
}

pub(crate) struct Proof<'a> {
    version_byte_and_envelope_hash: Digest,
    branches_before: &'a [u8],
    branches_after: &'a [u8],
}

pub(crate) enum TrieReadWithProof<'a> {
    Leaf(Leaf<'a>),
    BranchWithProof {
        digest: &'a Digest,
        proof: Proof<'a>,
    },
    NotFound,
}

pub(crate) type BranchIterator<'a> =
    Map<Chunks<'a, u8>, fn(&'a [u8]) -> Result<&'a Digest, TryFromSliceError>>;

impl<'a> Trie<'a> {
    pub(crate) fn new(trie_bytes: &[u8]) -> Trie {
        Trie(trie_bytes)
    }

    pub(crate) fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The tag code for the trie, which are the highest three bits of the first byte.
    /// This means there are 8 possible tags for a trie in total.
    pub(crate) fn tag(&self) -> TrieTag {
        match self.0[0] >> 5 {
            0 => TrieTag::Leaf,
            1 => TrieTag::Node31,
            2 => TrieTag::Node256,
            _ => TrieTag::Unknown,
        }
    }

    fn is_leaf(&self) -> bool {
        self.tag() == TrieTag::Leaf
    }

    /// Get the length in bytes of the branch index using the tag.
    /// - If the trie is a radix-31 node, the bottom 5 bits of the first byte determine the number
    ///   of bytes in the index.
    /// - If the trie is a radix-256 node, then the index length is always 32 bytes (ie, 256 bits)
    /// - If the trie is not a node this returns 0 bytes.
    pub(crate) fn branch_index_length(&self) -> u8 {
        match self.tag() {
            TrieTag::Node31 => self.0[0] & 0b11111,
            TrieTag::Node256 => 32,
            _ => 0,
        }
    }

    /// The second byte is the length of the Trie's key or affix in bytes.
    /// This means that keys are limited to having 256 bytes.
    pub(crate) fn key_or_affix_length(&self) -> usize {
        self.0[1] as usize
    }

    /// The key bytes if the trie is a leaf or the affix if it is a node. If the trie tag is
    /// neither of these then this is unspecified.
    pub(crate) fn key_or_affix(&self) -> &'a [u8] {
        &self.0[2..2 + self.key_or_affix_length()]
    }

    /// The byte indices of branches if the trie is a node. If the trie is not a node then this
    /// should return an empty slice.
    pub(crate) fn branch_byte_indices(&self) -> &'a [u8] {
        let offset_to_after_affix = 2 + self.key_or_affix_length();
        let search_index_length = self.branch_index_length();
        &self.0[offset_to_after_affix..offset_to_after_affix + search_index_length as usize]
    }

    /// The part of the trie before the branch hashes or value.
    /// Contains the tag and either the key + length or the affix, affix length and search index.
    fn envelope(&self) -> &'a [u8] {
        let offset_to_after_affix = 2 + self.key_or_affix_length();
        let search_index_length = self.branch_index_length();
        &self.0[0..offset_to_after_affix + search_index_length as usize]
    }

    /// The hash of the version byte and the envelope (ie, the part of the trie before the branch
    /// hashes or value).
    pub(crate) fn version_byte_and_envelope_hash(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[VERSION]);
        hasher.update(self.envelope());
        hasher.finalize()
    }

    /// Find the branch index for a byte in a trie node.
    /// For radix-31 nodes, use a binary search on the indices.
    /// For radix-256 nodes, use the popcnt instruction
    fn find_branch_byte(&self, key_byte_to_search_for: &u8) -> Option<u8> {
        let branch_byte_indices = self.branch_byte_indices();
        // TODO: Use SIMD if branch_byte_indices.len() <= 16 ?
        if branch_byte_indices.len() < 32 {
            return branch_byte_indices
                .binary_search(key_byte_to_search_for)
                .ok()
                .map(|index| index as u8);
        }

        // The 32 bytes in branch_byte_indices are a bit-array representing which bytes are present
        // as branches
        let (quot, rem) = (
            (key_byte_to_search_for / 64) as usize,
            (key_byte_to_search_for % 64) as usize,
        );

        // Make sure this branch is present before continuing
        let highest_bits = u64::from_le_bytes(
            branch_byte_indices[quot * 8..quot * 8 + 8]
                .try_into()
                .ok()?,
        );
        if highest_bits & (1u64 << rem) == 0 {
            return None;
        }

        let mut digest_index: u8 = 0;
        for i in 0..quot {
            // Convert blocks of 32 bytes into u64s, call popcnt to get how many branches in this
            // bit-array part
            let branch_count_in_bit_array =
                u64::from_le_bytes(branch_byte_indices[i * 8..i * 8 + 8].try_into().ok()?);
            digest_index += branch_count_in_bit_array.count_ones() as u8;
        }

        digest_index += (highest_bits & !(!0u64 << rem)).count_ones() as u8;
        Some(digest_index)
    }

    /// The value of the trie if it is a leaf. If the trie is not a leaf then this should return an
    /// empty slice.
    fn value(&self) -> &'a [u8] {
        if !self.is_leaf() {
            return &[];
        }
        let affix_length = self.key_or_affix_length();
        &self.0[2 + affix_length..]
    }

    /// The branch hashes of the trie if it is a node. If the trie is not a node then this should
    /// return an empty slice.
    fn branches(&self) -> &'a [u8] {
        if self.is_leaf() {
            return &[];
        }
        let affix_length = self.key_or_affix_length();
        let search_index_length = self.branch_index_length();
        &self.0[2 + affix_length + search_index_length as usize..]
    }

    pub(crate) fn get_nth_digest(
        &self,
        digest_index: u8,
    ) -> Result<TrieLeafOrBranch<'a>, TrieReadError> {
        if self.tag() == TrieTag::Leaf {
            return Ok(TrieLeafOrBranch::Leaf(Leaf(&self.0[1..])));
        }
        let branches = self.branches();
        let start_idx = digest_index as usize * DIGEST_LENGTH;
        if start_idx + DIGEST_LENGTH > branches.len() {
            Ok(TrieLeafOrBranch::IndexOutOfRange)
        } else {
            Ok(TrieLeafOrBranch::Branch(
                (&branches[start_idx..start_idx + DIGEST_LENGTH]).try_into()?,
            ))
        }
    }

    pub(crate) fn read_using_search_key(
        &self,
        search_key: &[u8],
        key_bytes_read: &mut u8,
    ) -> Result<TrieLeafOrBranch<'a>, TrieReadError> {
        // Determine what variant this trie is by reading the first byte for the code.
        // - the 3 highest bits are the branch code
        // - the 5 lowest bits are the branch count if the node has low radix
        let tag_code = self.tag();
        if tag_code == TrieTag::Leaf {
            let key = self.key_or_affix();
            // If the trie is a leaf but the key doesn't match our key, return KeyNotFound
            if key != search_key {
                return Ok(TrieLeafOrBranch::KeyNotFound);
            }
            return Ok(TrieLeafOrBranch::Leaf(Leaf(&self.0[1..])));
        }

        let affix = self.key_or_affix();

        // If the affix is not prefix of the keys bytes remaining, then return KeyNotFound
        if search_key.len() <= *key_bytes_read as usize + affix.len()
            || !search_key[*key_bytes_read as usize..].starts_with(affix)
        {
            return Ok(TrieLeafOrBranch::KeyNotFound);
        }

        // Find the next key byte after the affix from the index in the trie
        let key_byte_to_search_for = search_key[*key_bytes_read as usize + affix.len()];
        let digest_idx = match self.find_branch_byte(&key_byte_to_search_for) {
            None => return Ok(TrieLeafOrBranch::KeyNotFound),
            Some(digest_idx) => digest_idx as usize,
        };
        let branches = self.branches();
        let digest =
            branches[digest_idx * DIGEST_LENGTH..(digest_idx + 1) * DIGEST_LENGTH].try_into()?;

        *key_bytes_read += affix.len() as u8 + 1;
        Ok(TrieLeafOrBranch::Branch(digest))
    }

    pub(crate) fn read_with_proof_using_search_key(
        &self,
        search_key: &[u8],
        key_bytes_read: &mut u8,
    ) -> Result<TrieReadWithProof<'a>, TrieReadError> {
        // Determine what variant this trie is by reading the first byte for the code.
        // - the 3 highest bits are the branch code
        // - the 5 lowest bits are the branch count if the node has low radix
        let tag_code = self.tag();
        if tag_code == TrieTag::Leaf {
            let key = self.key_or_affix();
            // If the trie is a leaf but the key doesn't match our key, return NotFound
            if key != search_key {
                return Ok(TrieReadWithProof::NotFound);
            }
            return Ok(TrieReadWithProof::Leaf(Leaf(&self.0[1..])));
        }

        let affix = self.key_or_affix();

        // If the affix is not prefix of the keys bytes remaining, then return NotFound
        if search_key.len() <= *key_bytes_read as usize + affix.len()
            || !affix
                .iter()
                .zip(&search_key[*key_bytes_read as usize..])
                .all(|(affix_byte, key_byte)| affix_byte == key_byte)
        {
            return Ok(TrieReadWithProof::NotFound);
        }

        // Find the next key byte after the affix from the index in the trie
        let key_byte_to_search_for = search_key[*key_bytes_read as usize + affix.len()];
        let digest_idx = match self.find_branch_byte(&key_byte_to_search_for) {
            None => return Ok(TrieReadWithProof::NotFound),
            Some(digest_idx) => digest_idx as usize,
        };
        let branches = self.branches();
        let digest =
            branches[digest_idx * DIGEST_LENGTH..(digest_idx + 1) * DIGEST_LENGTH].try_into()?;

        *key_bytes_read += affix.len() as u8 + 1;
        Ok(TrieReadWithProof::BranchWithProof {
            digest,
            proof: Proof {
                version_byte_and_envelope_hash: self.version_byte_and_envelope_hash().into(),
                branches_before: &branches[..digest_idx * DIGEST_LENGTH],
                branches_after: &branches[(digest_idx + 1) * DIGEST_LENGTH..],
            },
        })
    }

    pub(crate) fn trie_hash(&self) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.version_byte_and_envelope_hash().as_bytes());
        if self.tag() == TrieTag::Leaf {
            // TODO: use Merkle/chunk hash for light clients / bridges
            hasher.update(self.value());
        } else {
            for digest in self.branches().chunks_exact(32) {
                hasher.update(digest);
            }
        }
        hasher.finalize().into()
    }

    pub(crate) fn iter_branch_digests(&self) -> BranchIterator<'a> {
        self.branches()
            .chunks(DIGEST_LENGTH)
            .map(<&Digest>::try_from)
    }

    fn iter_branch_indices(&'a self) -> TrieBranchIndexIterator<'a> {
        TrieBranchIndexIterator::new(self)
    }

    /// Iterate over the index/digest pairs in the trie.
    pub(crate) fn iter_branches(
        &'a self,
    ) -> impl Iterator<
        Item = (
            Result<u8, TryFromSliceError>,
            Result<&'a Digest, TryFromSliceError>,
        ),
    > {
        self.iter_branch_indices().zip(self.iter_branch_digests())
    }
}

pub(crate) enum TrieBranchIndexIterator<'a> {
    NotIterating, // TODO: get rid of this enum if we get rid of the Leaf/Unknown tags
    Node31(std::slice::Iter<'a, u8>),
    Node256 {
        bitvector: &'a [u8],
        index: u8,
        current_bit_vector_opt: Option<u64>,
    },
}

impl<'a> TrieBranchIndexIterator<'a> {
    fn new(trie: &'a Trie) -> Self {
        match trie.tag() {
            TrieTag::Leaf | TrieTag::Unknown => Self::NotIterating,
            TrieTag::Node31 => Self::Node31(trie.branch_byte_indices().iter()),
            TrieTag::Node256 => Self::Node256 {
                bitvector: trie.branch_byte_indices(),
                index: 0,
                current_bit_vector_opt: None,
            },
        }
    }
}

impl<'a> Iterator for TrieBranchIndexIterator<'a> {
    type Item = Result<u8, TryFromSliceError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            TrieBranchIndexIterator::NotIterating => None,
            TrieBranchIndexIterator::Node31(iterator) => iterator.next().cloned().map(Ok),
            TrieBranchIndexIterator::Node256 {
                bitvector,
                index,
                current_bit_vector_opt,
            } => {
                let current_bit_vector = loop {
                    if *index >= 4 {
                        return None;
                    }
                    let current_bit_vector = match current_bit_vector_opt {
                        Some(current_bit_vector) => *current_bit_vector,
                        None => {
                            let bit_vector_start_index = (*index * 8) as usize;
                            let current_bit_vector_result: Result<[u8; 8], TryFromSliceError> =
                                bitvector[bit_vector_start_index..bit_vector_start_index + 8]
                                    .try_into();
                            match current_bit_vector_result {
                                Ok(current_bit_vector) => u64::from_le_bytes(current_bit_vector),
                                Err(err) => {
                                    *index = 4;
                                    return Some(Err(err));
                                }
                            }
                        }
                    };
                    if current_bit_vector != 0 {
                        break current_bit_vector;
                    } else {
                        *index += 1;
                        *current_bit_vector_opt = None;
                    }
                };
                let j = current_bit_vector.trailing_zeros();
                *current_bit_vector_opt = Some(current_bit_vector - (1 << j));
                Some(Ok(j as u8 + *index * 64))
            }
        }
    }
}
