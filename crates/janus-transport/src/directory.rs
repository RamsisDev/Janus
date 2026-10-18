//! A network's nodes in one epoch, as its authorities publish them, and what a client derives
//! from them: the mailbox serving each queue, and the path of each packet.

use janus_core::QueueId;
use sha2::{Digest, Sha256};

use crate::shuffle;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Unique within a directory.
    pub name: String,
    /// Who runs it. No path holds two nodes of one operator.
    pub operator: String,
    /// Identifies the node; mailboxes are assigned by it.
    pub key: Vec<u8>,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    pub epoch: u64,
    /// Where clients connect.
    pub gateways: Vec<Node>,
    /// Mix layers in path order; every path crosses one node of each.
    pub layers: Vec<Vec<Node>>,
    pub mailboxes: Vec<Node>,
}

impl Directory {
    /// The mailbox serving `queue`: the one with the highest hash of the queue and its key
    /// (rendezvous hashing). Both sides find it with no message, and a mailbox that joins or
    /// leaves moves only the queues it takes or had.
    pub fn mailbox(&self, queue: &QueueId) -> Option<&Node> {
        self.mailboxes.iter().max_by_key(|node| {
            let score: [u8; 32] = Sha256::new()
                .chain_update(b"janus mailbox")
                .chain_update(queue)
                .chain_update(&node.key)
                .finalize()
                .into();
            score
        })
    }

    /// A random path from `gateway` to `mailbox`, one mix per layer, all of different
    /// operators: otherwise one operator would see both ends, the client's address and the
    /// queue it uses. `None` when no such path exists.
    pub fn path<'a>(&'a self, gateway: &'a Node, mailbox: &'a Node) -> Option<Vec<&'a Node>> {
        if gateway.operator == mailbox.operator {
            return None;
        }
        let mut operators = vec![gateway.operator.as_str(), mailbox.operator.as_str()];
        let mut path = vec![gateway];
        mixes(&self.layers, &mut operators, &mut path).then(|| {
            path.push(mailbox);
            path
        })
    }

    /// Gateways in the order to try them: random, but first those whose operator runs no
    /// mailbox, since a path never pairs a gateway with a mailbox of its operator.
    pub fn gateways(&self) -> Vec<&Node> {
        let mut order: Vec<&Node> = self.gateways.iter().collect();
        shuffle(&mut order);
        order.sort_by_key(|g| self.mailboxes.iter().any(|m| m.operator == g.operator));
        order
    }

    pub fn node(&self, name: &str) -> Option<&Node> {
        self.gateways
            .iter()
            .chain(self.layers.iter().flatten())
            .chain(&self.mailboxes)
            .find(|n| n.name == name)
    }
}

/// Fills `path` with one node per layer, none of an operator already in `operators`, trying
/// each layer's nodes in random order and backing up on a dead end.
fn mixes<'a>(
    layers: &'a [Vec<Node>],
    operators: &mut Vec<&'a str>,
    path: &mut Vec<&'a Node>,
) -> bool {
    let Some((layer, rest)) = layers.split_first() else {
        return true;
    };
    let mut order: Vec<&Node> = layer.iter().collect();
    shuffle(&mut order);
    for node in order {
        if operators.contains(&node.operator.as_str()) {
            continue;
        }
        operators.push(&node.operator);
        path.push(node);
        if mixes(rest, operators, path) {
            return true;
        }
        operators.pop();
        path.pop();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn node(name: &str, operator: &str) -> Node {
        Node {
            name: name.into(),
            operator: operator.into(),
            key: Sha256::digest(name.as_bytes()).to_vec(),
            addresses: vec![format!("{name}.example:4000")],
        }
    }

    /// Operators 1 to 4 run the mixes, so 3 layers leave room for the gateway's operator.
    fn directory() -> Directory {
        Directory {
            epoch: 1,
            gateways: vec![node("g1", "op5"), node("g2", "op6")],
            layers: vec![
                vec![node("m11", "op1"), node("m12", "op2")],
                vec![node("m21", "op2"), node("m22", "op3")],
                vec![node("m31", "op3"), node("m32", "op4")],
            ],
            mailboxes: (1..=4).map(|i| node(&format!("box{i}"), "op6")).collect(),
        }
    }

    #[test]
    fn paths_never_use_two_nodes_of_one_operator_and_vary() {
        let dir = directory();
        let (gateway, mailbox) = (&dir.gateways[0], &dir.mailboxes[0]);
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let path = dir.path(gateway, mailbox).unwrap();
            assert_eq!(path.len(), 5);
            assert_eq!((path[0], path[4]), (gateway, mailbox));
            let operators: HashSet<&str> = path.iter().map(|n| n.operator.as_str()).collect();
            assert_eq!(operators.len(), 5, "an operator twice: {path:?}");
            seen.insert(path.iter().map(|n| n.name.clone()).collect::<Vec<_>>());
        }
        assert!(seen.len() > 1, "always the same path");
    }

    #[test]
    fn no_path_when_the_operator_rule_cannot_hold() {
        let mut dir = directory();
        assert!(dir.path(&dir.gateways[1], &dir.mailboxes[0]).is_none());
        dir.layers[2] = vec![node("m31", "op5"), node("m32", "op6")];
        assert!(dir.path(&dir.gateways[0], &dir.mailboxes[0]).is_none());
    }

    #[test]
    fn gateways_whose_operator_runs_no_mailbox_come_first() {
        let dir = directory();
        for _ in 0..20 {
            assert_eq!(dir.gateways()[0].name, "g1");
        }
    }

    #[test]
    fn a_mailbox_leaving_moves_only_its_own_queues() {
        let dir = directory();
        let queues: Vec<QueueId> = (0..400u16)
            .map(|i| {
                let mut q = QueueId::default();
                q[..2].copy_from_slice(&i.to_be_bytes());
                q
            })
            .collect();
        let before: Vec<String> = queues
            .iter()
            .map(|q| dir.mailbox(q).unwrap().name.clone())
            .collect();
        for i in 1..=4 {
            let share = before.iter().filter(|n| **n == format!("box{i}")).count();
            assert!(share > 50, "box{i} serves only {share} of 400 queues");
        }
        let mut smaller = dir.clone();
        smaller.mailboxes.remove(1);
        for (q, was) in queues.iter().zip(&before) {
            let now = &smaller.mailbox(q).unwrap().name;
            assert!(was == "box2" || now == was, "{was} lost a queue to {now}");
        }
    }
}
