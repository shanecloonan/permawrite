//! G-8: deterministic partition, reorg, and equivocation harness.
//!
//! Two nodes extend a chain, stop hearing each other, then reconnect.
//! The longer chain wins. A key image spent only on the abandoned fork
//! is spendable again. Two blocks at the same height from the same
//! producer are equivocation and stay visible after the reorg.

use std::collections::{HashMap, HashSet};

use mfn_crypto::dhash;

#[derive(Clone, Debug)]
struct Block {
    parent: [u8; 32],
    height: u64,
    producer: u8,
    spend: Option<[u8; 32]>,
    id: [u8; 32],
}

fn block_id(parent: &[u8; 32], height: u64, producer: u8, spend: Option<[u8; 32]>) -> [u8; 32] {
    let mut body = Vec::with_capacity(8 + 1 + 1 + 32);
    body.extend_from_slice(&height.to_be_bytes());
    body.push(producer);
    match spend {
        Some(k) => {
            body.push(1);
            body.extend_from_slice(&k);
        }
        None => body.push(0),
    }
    dhash(b"MFN/g8-block", &[parent, &body])
}

struct Node {
    blocks: HashMap<[u8; 32], Block>,
    tip: [u8; 32],
}

impl Node {
    fn genesis() -> Self {
        let id = [0u8; 32];
        let genesis = Block {
            parent: id,
            height: 0,
            producer: 0,
            spend: None,
            id,
        };
        let mut blocks = HashMap::new();
        blocks.insert(id, genesis);
        Self { blocks, tip: id }
    }

    fn tip_block(&self) -> &Block {
        &self.blocks[&self.tip]
    }

    fn extend(&mut self, producer: u8, spend: Option<[u8; 32]>) -> [u8; 32] {
        let parent = self.tip_block();
        let height = parent.height + 1;
        let id = block_id(&parent.id, height, producer, spend);
        let block = Block {
            parent: parent.id,
            height,
            producer,
            spend,
            id,
        };
        self.blocks.insert(id, block);
        self.tip = id;
        id
    }

    fn chain(&self, tip: [u8; 32]) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        let mut cursor = tip;
        for _ in 0..10_000 {
            let Some(block) = self.blocks.get(&cursor) else {
                break;
            };
            out.push(cursor);
            if block.height == 0 {
                break;
            }
            cursor = block.parent;
        }
        out.reverse();
        out
    }

    fn spent(&self) -> HashSet<[u8; 32]> {
        let mut spent = HashSet::new();
        for id in self.chain(self.tip) {
            if let Some(key) = self.blocks[&id].spend {
                spent.insert(key);
            }
        }
        spent
    }

    /// Adopt `remote_tip` when its chain is strictly taller and every
    /// ancestor is already known. Returns true when the tip moved.
    fn reorg_to(&mut self, remote_tip: [u8; 32]) -> bool {
        let Some(remote) = self.blocks.get(&remote_tip) else {
            return false;
        };
        if remote.height <= self.tip_block().height {
            return false;
        }
        let chain = self.chain(remote_tip);
        if chain.first() != Some(&[0u8; 32]) {
            return false;
        }
        self.tip = remote_tip;
        true
    }

    fn ingest(&mut self, block: Block) {
        self.blocks.insert(block.id, block);
    }

    /// Producers who signed two different blocks at one height.
    fn equivocations(&self) -> Vec<(u8, u64)> {
        let mut at: HashMap<(u8, u64), [u8; 32]> = HashMap::new();
        let mut out = Vec::new();
        for block in self.blocks.values() {
            if block.height == 0 {
                continue;
            }
            let key = (block.producer, block.height);
            if let Some(prev) = at.insert(key, block.id) {
                if prev != block.id && !out.contains(&key) {
                    out.push(key);
                }
            }
        }
        out.sort_unstable();
        out
    }
}

fn share(dst: &mut Node, src: &Node) {
    for block in src.blocks.values() {
        dst.ingest(block.clone());
    }
}

#[test]
fn partition_then_reorg_drops_the_shorter_forks_spend() {
    let mut alice = Node::genesis();
    let mut bob = Node::genesis();
    let image = [0x11u8; 32];

    // Alice keeps producing through the partition. Bob spends once and stalls.
    alice.extend(1, None);
    alice.extend(1, None);
    alice.extend(1, None);
    bob.extend(2, Some(image));

    assert!(!alice.spent().contains(&image));
    assert!(bob.spent().contains(&image));
    assert_eq!(alice.tip_block().height, 3);
    assert_eq!(bob.tip_block().height, 1);

    share(&mut bob, &alice);
    assert!(bob.reorg_to(alice.tip));
    assert_eq!(bob.tip, alice.tip);
    assert!(!bob.spent().contains(&image));

    // A third node that only saw Bob's short fork must drop that spend
    // when it adopts Alice's chain, which does not include Bob's block.
    let mut carol = Node::genesis();
    let bob_only = {
        let mut n = Node::genesis();
        n.extend(2, Some(image));
        n
    };
    share(&mut carol, &bob_only);
    assert!(carol.reorg_to(bob_only.tip));
    assert!(carol.spent().contains(&image));
    share(&mut carol, &alice);
    assert!(carol.reorg_to(alice.tip));
    assert!(!carol.spent().contains(&image));
    assert!(carol.extend(3, Some(image)) != [0u8; 32]);
    assert!(carol.spent().contains(&image));
}

#[test]
fn equivocation_survives_the_reorg() {
    let mut alice = Node::genesis();
    let parent = alice.tip;
    let a = {
        let mut n = Node::genesis();
        n.tip = parent;
        n.extend(7, None)
    };
    let b = {
        let mut n = Node::genesis();
        n.tip = parent;
        n.extend(7, Some([9u8; 32]))
    };
    assert_ne!(a, b);

    // Both seals are from producer 7 at height 1.
    alice.ingest(Block {
        parent,
        height: 1,
        producer: 7,
        spend: None,
        id: a,
    });
    alice.ingest(Block {
        parent,
        height: 1,
        producer: 7,
        spend: Some([9u8; 32]),
        id: b,
    });
    // Grow one side so a peer reorgs onto it and still remembers both seals.
    alice.tip = a;
    alice.extend(1, None);
    let evidence = alice.equivocations();
    assert_eq!(evidence, vec![(7, 1)]);

    let mut bob = Node::genesis();
    bob.tip = b;
    bob.ingest(Block {
        parent,
        height: 1,
        producer: 7,
        spend: Some([9u8; 32]),
        id: b,
    });
    share(&mut bob, &alice);
    assert!(bob.reorg_to(alice.tip));
    assert_eq!(bob.equivocations(), vec![(7, 1)]);
}

#[test]
fn shorter_chain_does_not_reorg_a_taller_node() {
    let mut tall = Node::genesis();
    tall.extend(1, None);
    tall.extend(1, None);
    let mut short = Node::genesis();
    short.extend(2, None);
    share(&mut tall, &short);
    assert!(!tall.reorg_to(short.tip));
    assert_eq!(tall.tip_block().height, 2);
}

#[test]
fn same_key_image_on_both_sides_of_a_partition_conflicts_on_heal() {
    let image = [0x42u8; 32];
    let mut alice = Node::genesis();
    let mut bob = Node::genesis();
    alice.extend(1, Some(image));
    bob.extend(2, Some(image));
    share(&mut alice, &bob);
    share(&mut bob, &alice);
    // Neither chain is taller, so neither reorgs. Both spends are visible
    // as competing forks, which is the conflict a healer has to keep.
    assert!(!alice.reorg_to(bob.tip));
    assert!(!bob.reorg_to(alice.tip));
    assert_ne!(alice.tip, bob.tip);
    let spenders: HashSet<[u8; 32]> = alice
        .blocks
        .values()
        .chain(bob.blocks.values())
        .filter(|b| b.spend == Some(image))
        .map(|b| b.id)
        .collect();
    assert_eq!(spenders.len(), 2);
}
