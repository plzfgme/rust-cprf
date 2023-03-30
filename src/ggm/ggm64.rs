use std::collections::VecDeque;

use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128Enc,
};
use arrayvec::ArrayVec;
use bitvec::prelude::*;
use generic_array::{arr, typenum::U16, GenericArray};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

pub const GGM64_KEYSIZE: usize = 16;
pub const GGM64_OUTPUTSIZE: usize = 16;

type Ggm64Node = GenericArray<u8, U16>;
pub type Ggm64Output = [u8; GGM64_OUTPUTSIZE];

lazy_static! {
    static ref BLOCK0: GenericArray<u8, U16> = arr![u8; 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    static ref BLOCK1: GenericArray<u8, U16> = arr![u8; 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Ggm64MasterKey {
    key: Ggm64Node,
}

impl Ggm64MasterKey {
    pub fn new(key: [u8; GGM64_KEYSIZE]) -> Ggm64MasterKey {
        Ggm64MasterKey {
            key: Ggm64Node::from(key),
        }
    }

    pub fn new_from_slice(key: &[u8]) -> Ggm64MasterKey {
        assert!(key.len() >= GGM64_KEYSIZE);

        Ggm64MasterKey {
            key: *Ggm64Node::from_slice(&key[..GGM64_KEYSIZE]),
        }
    }

    pub fn evaluate(&self, input: u64) -> Ggm64Output {
        let mut node = self.key;

        input
            .view_bits::<Msb0>()
            .iter()
            .for_each(|b| step(&mut node, *b));

        node.into()
    }

    pub fn constrain(&self, a: u64, b: u64) -> Ggm64ConstrainedKey {
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

        if b_bits[..t].all() {
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Ggm64ConstrainedKey {
    a: u64,
    b: u64,
    node_prefixs: VecDeque<(u8, u64)>,
    nodes: VecDeque<Ggm64Node>,
}

impl Ggm64ConstrainedKey {
    pub fn get_range(&self) -> (u64, u64) {
        (self.a, self.b)
    }

    pub fn evaluate(&self, input: u64) -> Option<Ggm64Output> {
        let (prefix_length, mut node) = match self.search(input) {
            Some((l, n)) => (l as usize, n),
            None => return None,
        };

        let input = input.view_bits::<Msb0>();

        input[prefix_length..]
            .iter()
            .for_each(|b| step(&mut node, *b));

        Some(node.into())
    }

    pub fn evaluate_all(&self) -> GgmRCPrfIterator {
        GgmRCPrfIterator {
            ckey: self,
            current_tree: 0,
            stack: ArrayVec::new(),
            current: Some((self.node_prefixs[0].0, self.nodes[0])),
        }
    }

    fn search(&self, target: u64) -> Option<(u8, Ggm64Node)> {
        let (mut low, mut high) = (0, self.node_prefixs.len());

        if target < self.a || target > self.b {
            return None;
        }

        while low < high {
            let mid = (low + high) / 2;
            let node_prefix = self.node_prefixs[mid];

            match node_prefix.1.cmp(&target) {
                std::cmp::Ordering::Equal => return Some((node_prefix.0, self.nodes[mid])),
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Less => {
                    if keep_first_n_bit_set_others_one(node_prefix.1, node_prefix.0) < target {
                        low = mid + 1;
                    } else {
                        return Some((node_prefix.0, self.nodes[mid]));
                    }
                }
            }
        }

        None
    }
}

pub struct GgmRCPrfIterator<'a> {
    ckey: &'a Ggm64ConstrainedKey,
    current_tree: usize,
    stack: ArrayVec<(u8, Ggm64Node), 64>,
    current: Option<(u8, Ggm64Node)>,
}

impl<'a> GgmRCPrfIterator<'a> {
    fn next_in_one_tree(&mut self) -> Option<Ggm64Output> {
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

impl<'a> Iterator for GgmRCPrfIterator<'a> {
    type Item = Ggm64Output;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(output) = self.next_in_one_tree() {
            Some(output)
        } else if self.current_tree < self.ckey.node_prefixs.len() - 1 {
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
        let size = (self.ckey.b - self.ckey.a + 1) as usize;

        (size, Some(size))
    }
}

#[inline(always)]
fn step(node: &mut Ggm64Node, b: bool) {
    let cipher = Aes128Enc::new(node);

    match b {
        true => cipher.encrypt_block_b2b(&BLOCK1, node),
        false => cipher.encrypt_block_b2b(&BLOCK0, node),
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
