use std::collections::VecDeque;

use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128Enc,
};
use arrayvec::ArrayVec;
use bitvec::prelude::*;
use generic_array::{typenum::U16, GenericArray};
use serde::{Deserialize, Serialize};

/// Key size of Ggm64.
pub const GGM64_KEYSIZE: usize = 16;
/// Output size of Ggm64.
pub const GGM64_OUTPUTSIZE: usize = 16;
/// Key type of Ggm64
pub type Ggm64Key = [u8; GGM64_KEYSIZE];
/// Output type of Ggm64's evaluation result.
pub type Ggm64Output = [u8; GGM64_OUTPUTSIZE];

const GGM64_NODESIZE: usize = 16;
type Ggm64NodeArray = [u8; GGM64_NODESIZE];
type Ggm64Node = GenericArray<u8, U16>; // GGM internal result

const BLOCK0: Ggm64NodeArray = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const BLOCK1: Ggm64NodeArray = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// Master key of GGM range-constrained PRF, uses u64 as input.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ggm64MasterKey {
    key: Ggm64Node,
}

/// Master key of GGM range-constrained PRF, uses u64 as input.
impl Ggm64MasterKey {
    /// Creates master key from array.
    pub fn new(key: Ggm64Key) -> Ggm64MasterKey {
        Ggm64MasterKey {
            key: Ggm64Node::from(key),
        }
    }

    /// Creates master key from slice.
    ///
    /// Panic if key.len() is not sufficent.
    pub fn new_from_slice(key: &[u8]) -> Ggm64MasterKey {
        assert!(key.len() >= GGM64_KEYSIZE);

        Ggm64MasterKey {
            key: *Ggm64Node::from_slice(&key[..GGM64_KEYSIZE]),
        }
    }

    /// Evaluates the input.
    pub fn evaluate(&self, input: u64) -> Ggm64Output {
        let mut node = self.key;

        input
            .view_bits::<Msb0>()
            .iter()
            .for_each(|b| step(&mut node, *b));

        node.into()
    }

    /// Generates a constrained key for [a, b].
    ///
    /// Panic if a > b.
    pub fn constrain(&self, a: u64, b: u64) -> Ggm64ConstrainedKey {
        assert!(a <= b);

        // Below algorithm is based on best range cover.

        let (a_bits, b_bits) = (a.view_bits::<Msb0>(), b.view_bits::<Msb0>());

        let mut node_prefixs = VecDeque::with_capacity(2 * 64_usize);
        let mut nodes = VecDeque::with_capacity(2 * 64_usize);

        let mut node = self.key;

        let mut t = 0;
        while t < 64 {
            if a_bits[t] != b_bits[t] {
                break;
            }
            step(&mut node, a_bits[t]);

            t += 1;
        }

        let mut a_node = node;
        if a_bits[t..].not_any() {
            if b_bits[t..].all() {
                node_prefixs.push_front((t as u8, keep_first_n_bit_set_others_zero(a, t)));
                nodes.push_front(a_node);

                return Ggm64ConstrainedKey {
                    a,
                    b,
                    node_prefixs,
                    nodes,
                };
            } else {
                node_prefixs
                    .push_front(((t + 1) as u8, keep_first_n_bit_set_others_zero(a, t + 1)));
                step(&mut a_node, a_bits[t]);
                nodes.push_front(a_node);
            }
        } else {
            step(&mut a_node, a_bits[t]);
            let mut u = 63;
            while u > t {
                if a_bits[u] {
                    break;
                }

                u -= 1;
            }

            let mut i = t + 1;
            while i < u {
                if !a_bits[i] {
                    node_prefixs.push_front((
                        (i + 1) as u8,
                        set_bit(keep_first_n_bit_set_others_zero(a, i), i, true),
                    ));
                    let mut tmp_node = a_node;
                    step(&mut tmp_node, true);
                    nodes.push_front(tmp_node);
                }
                step(&mut a_node, a_bits[i]);

                i += 1;
            }
            node_prefixs.push_front(((u + 1) as u8, keep_first_n_bit_set_others_zero(a, u + 1)));
            step(&mut a_node, a_bits[u]);
            nodes.push_front(a_node);
        }

        if b_bits[t..].all() {
            node_prefixs.push_back(((t + 1) as u8, keep_first_n_bit_set_others_zero(b, t + 1)));
            step(&mut node, b_bits[t]);
            nodes.push_back(node);
        } else {
            step(&mut node, b_bits[t]);
            let mut v = 63;
            while v > t {
                if !b_bits[v] {
                    break;
                }

                v -= 1;
            }

            let mut i = t + 1;
            while i < v {
                if b_bits[i] {
                    node_prefixs.push_back((
                        (i + 1) as u8,
                        set_bit(keep_first_n_bit_set_others_zero(b, i), i, false),
                    ));
                    let mut tmp_node = node;
                    step(&mut tmp_node, false);
                    nodes.push_back(tmp_node);
                }
                step(&mut node, b_bits[i]);

                i += 1;
            }
            node_prefixs.push_back(((v + 1) as u8, keep_first_n_bit_set_others_zero(b, v + 1)));
            step(&mut node, b_bits[v]);
            nodes.push_back(node);
        }

        Ggm64ConstrainedKey {
            a,
            b,
            node_prefixs,
            nodes,
        }
    }
}

/// Constrained key of GGM range-constrained PRF, uses u64 as input.
///
/// Generated by [`Ggm64MasterKey::constrain`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ggm64ConstrainedKey {
    a: u64,
    b: u64,
    node_prefixs: VecDeque<(u8, u64)>, // (prefix_length, number_of_node (all 0 except the prefix bits)), order by number_of_node
    nodes: VecDeque<Ggm64Node>,        // nodes (GGM internal result)
}

impl Ggm64ConstrainedKey {
    /// Gets the valid range [a, b] of the key.
    pub fn get_range(&self) -> (u64, u64) {
        (self.a, self.b)
    }

    /// Evaluates the input.
    ///
    /// Returns None if input is invalid.
    pub fn evaluate(&self, input: u64) -> Option<Ggm64Output> {
        let (prefix_length, mut node) = match self.search_for_root(input) {
            Some((_, (l, n))) => (l, n),
            None => return None,
        };

        let input = input.view_bits::<Msb0>();

        input[(prefix_length as usize)..]
            .iter()
            .for_each(|b| step(&mut node, *b));

        Some(node.into())
    }

    /// Evaluates all valid input of the constrained key.
    ///
    /// Returns a iterator of evaluation output.
    pub fn evaluate_all(&self) -> Ggm64Iterator {
        Ggm64Iterator {
            start: self.a,
            count: self.b - self.a + 1,
            size: self.b - self.a + 1,
            ckey: self,
            current_tree: 0,
            stack: ArrayVec::new(),
            current: Some((self.node_prefixs[0].0, self.nodes[0])),
        }
    }

    /// Evaluate all valid input of range [a, b].
    ///
    /// If [a, b] is invalid or wrong, returns None, else returns a iterator of evaluation output.
    pub fn evaluate_range(&self, a: u64, b: u64) -> Option<Ggm64Iterator> {
        if a < self.a || b > self.b || a > b {
            return None;
        }

        let (current_tree, (prefix_length, mut node)) = match self.search_for_root(a) {
            Some(x) => x,
            None => return None,
        };

        let a_bits = a.view_bits::<Msb0>();
        let mut stack = ArrayVec::new();
        let mut i = prefix_length;
        a_bits[(prefix_length as usize)..].iter().for_each(|b| {
            if !*b {
                stack.push((i, node));
            }
            step(&mut node, *b);
            i += 1;
        });

        Some(Ggm64Iterator {
            start: a,
            count: b - a + 1,
            size: b - a + 1,
            ckey: self,
            current_tree,
            stack,
            current: Some((i, node)),
        })
    }

    /// Searchs for the tree root corresponding to the target.
    fn search_for_root(&self, target: u64) -> Option<(usize, (u8, Ggm64Node))> {
        let (mut low, mut high) = (0, self.node_prefixs.len());

        if target < self.a || target > self.b {
            return None;
        }

        while low < high {
            let mid = (low + high) / 2;
            let node_prefix = self.node_prefixs[mid];

            match node_prefix.1.cmp(&target) {
                std::cmp::Ordering::Equal => return Some((mid, (node_prefix.0, self.nodes[mid]))),
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Less => {
                    if keep_first_n_bit_set_others_one(node_prefix.1, node_prefix.0) < target {
                        low = mid + 1;
                    } else {
                        return Some((mid, (node_prefix.0, self.nodes[mid])));
                    }
                }
            }
        }

        None
    }
}

/// Iterator over a range of input, produces evaluation results of Ggm64.
#[derive(Debug)]
pub struct Ggm64Iterator<'a> {
    start: u64,
    count: u64, // Remained results need to be output.
    size: u64,
    ckey: &'a Ggm64ConstrainedKey,

    // Every node in the constraind key is a root of tree.
    // We need to calculate the output for every leaf node.
    current_tree: usize,

    // Inorder traversal data structs.
    stack: ArrayVec<(u8, Ggm64Node), 65>,
    current: Option<(u8, Ggm64Node)>,
}

impl<'a> Ggm64Iterator<'a> {
    pub fn range(&self) -> (u64, u64) {
        (self.start, self.start + self.size - 1)
    }

    /// Caluates the next output in one tree.
    fn next_in_one_tree(&mut self) -> Option<Ggm64Output> {
        // Inorder traversal.
        while self.current.is_some() || !self.stack.is_empty() {
            while let Some(node) = self.current.as_mut() {
                self.stack.push(*node);
                if node.0 == 64 {
                    self.current = None;
                } else {
                    node.0 += 1;
                    step(&mut node.1, false);
                }
            }
            if let Some(mut node) = self.stack.pop() {
                if node.0 == 64 {
                    self.current = None;
                    return Some(node.1.into());
                } else {
                    node.0 += 1;
                    step(&mut node.1, true);
                    self.current = Some(node);
                };
            }
        }

        None
    }
}

impl<'a> Iterator for Ggm64Iterator<'a> {
    type Item = Ggm64Output;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }

        if let Some(output) = self.next_in_one_tree() {
            self.count -= 1;
            Some(output)
        } else if self.current_tree < self.ckey.node_prefixs.len() - 1 {
            // Switch to next tree.
            self.current_tree += 1;
            self.current = Some((
                self.ckey.node_prefixs[self.current_tree].0,
                self.ckey.nodes[self.current_tree],
            ));
            self.next()
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.size as usize, Some(self.size as usize))
    }
}

#[inline(always)]
fn step(node: &mut Ggm64Node, b: bool) {
    // Uses AES-CTR DRBG
    let cipher = Aes128Enc::new(node);

    let block0 = GenericArray::from_slice(&BLOCK0);
    let block1 = GenericArray::from_slice(&BLOCK1);

    match b {
        true => cipher.encrypt_block_b2b(block1, node),
        false => cipher.encrypt_block_b2b(block0, node),
    }
}

#[inline(always)]
fn keep_first_n_bit_set_others_zero(x: u64, n: usize) -> u64 {
    x & !((1 << (64 - n)) - 1)
}

#[inline(always)]
fn keep_first_n_bit_set_others_one(x: u64, n: u8) -> u64 {
    x | ((1 << (64 - n)) - 1)
}

#[inline(always)]
fn set_bit(x: u64, n: usize, b: bool) -> u64 {
    let x = x & !(1u64 << (63 - n));

    x | ((b as u64) << (63 - n))
}

#[cfg(test)]
mod tests {
    use crate::ggm::{Ggm64MasterKey, GGM64_KEYSIZE};

    use super::Ggm64Output;

    #[test]
    fn ck_eval_ok() {
        let key = [0u8; GGM64_KEYSIZE];
        let mk = Ggm64MasterKey::new_from_slice(&key);
        let mk_output = mk.evaluate(2500);

        let ck = mk.constrain(2000, 3000);
        let ck_output = ck.evaluate(2500).unwrap();

        assert_eq!(mk_output, ck_output);
    }

    #[test]
    fn ck_eval_none() {
        let key = [0u8; GGM64_KEYSIZE];
        let mk = Ggm64MasterKey::new_from_slice(&key);

        let ck = mk.constrain(2000, 3000);

        assert!(ck.evaluate(1500).is_none());
        assert!(ck.evaluate(3444).is_none());
    }

    #[test]
    fn ck_eval_all_ok() {
        let key = [0u8; GGM64_KEYSIZE];
        let mk = Ggm64MasterKey::new_from_slice(&key);
        let mut mk_outputs = Vec::with_capacity(21);
        for input in 2700..=2720 {
            mk_outputs.push(mk.evaluate(input));
        }

        let ck = mk.constrain(2700, 2720);
        let ck_outputs: Vec<Ggm64Output> = ck.evaluate_all().collect();

        assert_eq!(mk_outputs, ck_outputs)
    }

    #[test]
    fn ck_eval_range_ok() {
        let key = [0u8; GGM64_KEYSIZE];
        let mk = Ggm64MasterKey::new_from_slice(&key);
        let mut mk_outputs = Vec::with_capacity(21);
        for input in 2700..=2720 {
            mk_outputs.push(mk.evaluate(input));
        }

        let ck = mk.constrain(2000, 3000);
        let ck_outputs: Vec<Ggm64Output> = ck.evaluate_range(2700, 2720).unwrap().collect();

        assert_eq!(mk_outputs, ck_outputs)
    }

    #[test]
    fn ck_eval_range_none() {
        let key = [0u8; GGM64_KEYSIZE];
        let mk = Ggm64MasterKey::new_from_slice(&key);

        let ck = mk.constrain(2000, 3000);

        assert!(ck.evaluate_range(1700, 2720).is_none());
        assert!(ck.evaluate_range(1700, 3720).is_none());
        assert!(ck.evaluate_range(2700, 3720).is_none());
        assert!(ck.evaluate_range(2700, 2620).is_none());
    }
}
