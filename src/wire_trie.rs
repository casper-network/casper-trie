pub const DIGEST_LENGTH: usize = 32;
pub type Digest = [u8; DIGEST_LENGTH];
pub const EMPTY_TRIE_ROOT: [u8; DIGEST_LENGTH] = [0u8; DIGEST_LENGTH];

const VERSION: u8 = 0;

/// A wire-format for a Merkle Patricia trie. This is a new-type around raw bytes. The raw bytes
/// have two components.
///
/// The two components are:
/// 1. An *envelope*
/// 2. A *value* or list of cryptographic hashes representing branches.
///
/// The envelope has the following byte structure:
///
/// Byte 1:
///   - A tag encoded as the most significant 3 bits
///   - A branch count encoded as the least significant 5 bits when this is a NODE31_TYPE
///
/// Byte 2: Key or affix length.
///
/// Bytes 3 to at most 256+3: The key or affix. These bytes are for a key if the highest three
/// bits in byte 1 were LEAF_TAG (ie, 0). Otherwise it is an affix, because the trie is a node with
/// branches.
///   - Having a keyspace that supports keys 256 bytes in length is helpful for variable length
///     keys. One might have entities which have a sub-map associated with them. This is supported
///     provided that no key is a prefix of another key.
/// The next bytes depend on the type.
///
///   - LEAF_TYPE - these are the values of the leaf, represented as a blob of bytes
///   - NODE31_TYPE - this type has: + Search index bytes, with length indicated by the bottom 5
///     bits of the first byte. These bytes are always in order so we can use binary searches. + A
///     list of hashes. Each hash is DIGEST_LENGTH (ie, 32) bytes long. The length of this list is
///     the same as the bottom 5 bits of the first byte.
///   - NODE32_TYPE - this type has: + A bitmask of 32 bytes (256 bits) + A list fo hashes.
///
/// Nodes cannot have 0 branches or just 1 branch.

#[derive(PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    Leaf = 0,
    Node31 = 1,
    Node256 = 2,
    Unknown = 255,
}

pub struct Trie<'a>(&'a [u8]);

pub type TrieReadError = std::array::TryFromSliceError;

#[derive(Debug, Clone)]
// TODO: Don't be pub (crate)
pub struct Leaf<'a>(pub(crate) &'a [u8]);

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

    fn value(&self) -> &[u8] {
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
    version_byte_and_envelop_hash: Digest,
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

impl<'a> Trie<'a> {
    pub(crate) fn new(trie_bytes: &[u8]) -> Trie {
        Trie(trie_bytes)
    }

    pub(crate) fn raw_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// The tag code for the trie, which are the highest three bits of the first byte.
    /// This means there are 8 possible tags for a trie in total.
    pub(crate) fn tag(&self) -> Tag {
        match self.0[0] >> 5 {
            0 => Tag::Leaf,
            1 => Tag::Node31,
            2 => Tag::Node256,
            _ => Tag::Unknown,
        }
    }

    /// Get the length in bytes of the branch index using the tag.
    /// - If the trie is a radix-31 node, the bottom 5 bits of the first byte determine the number
    ///   of bytes in the index.
    /// - If the trie is a radix-256 node, then the index length is always 32 bytes (ie, 256 bits)
    /// - If the trie is not a node this returns 0 bytes.
    fn search_index_length(&self) -> usize {
        match self.tag() {
            Tag::Node31 => self.0[0] as usize & 0b11111,
            Tag::Node256 => 32,
            _ => 0,
        }
    }

    /// The second byte is the length of the Trie's key or affix in bytes.
    /// This means that keys are limited to having 256 bytes.
    fn key_or_affix_length(&self) -> usize {
        self.0[1] as usize
    }

    /// The key bytes if the trie is a leaf or the affix if it is a node. If the trie tag is
    /// neither of these then this is unspecified.
    pub(crate) fn key_or_affix(&self) -> &'a [u8] {
        &self.0[2..2 + self.key_or_affix_length()]
    }

    /// The byte indices of branches if the trie is a node. If the trie is not a node then this
    /// should return an empty slice.
    fn branch_byte_indices(&self) -> &'a [u8] {
        let offset_to_after_affix = 2 + self.key_or_affix_length();
        let search_index_length = self.search_index_length();
        &self.0[offset_to_after_affix..offset_to_after_affix + search_index_length]
    }

    /// The part of the trie before the branch hashes or value.
    /// Contains the tag and either the key + length or the affix, affix length and search index.
    fn envelope(&self) -> &'a [u8] {
        let offset_to_after_affix = 2 + self.key_or_affix_length();
        let search_index_length = self.search_index_length();
        &self.0[0..offset_to_after_affix + search_index_length]
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

    /// The value of a trie leaf, or the Digest branches of a trie node. If the trie is neither a
    /// leaf nor a node then this is unspecified.
    fn value_or_branches(&self) -> &'a [u8] {
        let affix_length = self.key_or_affix_length();
        let search_index_length = self.search_index_length();
        &self.0[2 + affix_length + search_index_length..]
    }

    pub(crate) fn get_nth_digest(
        &self,
        digest_index: u8,
    ) -> Result<TrieLeafOrBranch<'a>, TrieReadError> {
        if self.tag() == Tag::Leaf {
            return Ok(TrieLeafOrBranch::Leaf(Leaf(&self.0[1..])));
        }
        let branches = self.value_or_branches();
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
        if tag_code == Tag::Leaf {
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
            || !affix
                .iter()
                .zip(&search_key[*key_bytes_read as usize..])
                .all(|(affix_byte, key_byte)| affix_byte == key_byte)
        {
            return Ok(TrieLeafOrBranch::KeyNotFound);
        }

        // Find the next key byte after the affix from the index in the trie
        let key_byte_to_search_for = search_key[*key_bytes_read as usize + affix.len()];
        let digest_idx = match self.find_branch_byte(&key_byte_to_search_for) {
            None => return Ok(TrieLeafOrBranch::KeyNotFound),
            Some(digest_idx) => digest_idx as usize,
        };
        let branches = self.value_or_branches();
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
        if tag_code == Tag::Leaf {
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
        let branches = self.value_or_branches();
        let digest =
            branches[digest_idx * DIGEST_LENGTH..(digest_idx + 1) * DIGEST_LENGTH].try_into()?;

        *key_bytes_read += affix.len() as u8 + 1;
        Ok(TrieReadWithProof::BranchWithProof {
            digest,
            proof: Proof {
                version_byte_and_envelop_hash: self.version_byte_and_envelope_hash().into(),
                branches_before: &branches[..digest_idx * DIGEST_LENGTH],
                branches_after: &branches[(digest_idx + 1) * DIGEST_LENGTH..],
            },
        })
    }

    pub(crate) fn trie_hash(&self) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.version_byte_and_envelope_hash().as_bytes());
        if self.tag() == Tag::Leaf {
            // TODO: use Merkle/chunk hash for light clients / bridges
            hasher.update(self.value_or_branches());
        } else {
            for digest in self.value_or_branches().chunks_exact(32) {
                hasher.update(digest);
            }
        }
        hasher.finalize().into()
    }
}
