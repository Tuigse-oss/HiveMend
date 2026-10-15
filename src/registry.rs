use std::collections::BTreeMap;

use crate::model::{RegValue, ValueKind};
use crate::pathutil::canonical_path;

#[derive(Debug)]
pub enum RegError {
    NotFound,
    /// Access denied, usually a machine-wide key in a process that is not elevated.
    Denied(String),
    Message(String),
}

impl std::fmt::Display for RegError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("registry key not found"),
            Self::Denied(message) | Self::Message(message) => f.write_str(message),
        }
    }
}

pub trait Registry {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError>;
    fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError>;
    fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError>;
    fn delete_tree(&mut self, path: &str) -> Result<(), RegError>;
    /// Write one value, creating the key and any missing parents. Windows
    /// refuses to write through a registry link.
    fn set_value(&mut self, path: &str, name: &str, data: &ValueKind) -> Result<(), RegError> {
        let _ = (path, name, data);
        Err(RegError::Message("this registry cannot be written".into()))
    }
}

#[derive(Clone, Debug, Default)]
struct Node {
    values: BTreeMap<String, ValueKind>,
    children: Vec<NodeChild>,
}

#[derive(Clone, Debug)]
struct NodeChild {
    name: String,
    node: Node,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryRegistry {
    root: Node,
}

impl MemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, path: &str, name: &str, data: ValueKind) {
        let path = canonical_path(path);
        let mut node = &mut self.root;
        if !path.is_empty() {
            for part in path.split('\\') {
                let index = child_index(&node.children, part);
                if index.is_none() {
                    node.children.push(NodeChild {
                        name: part.to_string(),
                        node: Node::default(),
                    });
                }
                let index = child_index(&node.children, part).expect("child just inserted");
                node = &mut node.children[index].node;
            }
        }
        if let Some(existing) = node
            .values
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            *existing.1 = data;
        } else {
            node.values.insert(name.to_string(), data);
        }
    }

    pub fn set_sz(&mut self, path: &str, name: &str, data: &str) {
        self.set(path, name, ValueKind::Sz(data.to_string()));
    }

    pub fn set_dword(&mut self, path: &str, name: &str, data: u32) {
        self.set(path, name, ValueKind::Dword(data));
    }

    fn node(&self, path: &str) -> Option<&Node> {
        let path = canonical_path(path);
        let mut node = &self.root;
        if path.is_empty() {
            return Some(node);
        }
        for part in path.split('\\') {
            let index = child_index(&node.children, part)?;
            node = &node.children[index].node;
        }
        Some(node)
    }

    fn node_mut(&mut self, path: &str) -> Option<&mut Node> {
        let path = canonical_path(path);
        let mut node = &mut self.root;
        if path.is_empty() {
            return Some(node);
        }
        for part in path.split('\\') {
            let index = child_index(&node.children, part)?;
            node = &mut node.children[index].node;
        }
        Some(node)
    }
}

fn child_index(children: &[NodeChild], name: &str) -> Option<usize> {
    children
        .iter()
        .position(|child| child.name.eq_ignore_ascii_case(name))
}

impl Registry for MemoryRegistry {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
        let node = self.node(path).ok_or(RegError::NotFound)?;
        Ok(node
            .children
            .iter()
            .map(|child| child.name.clone())
            .collect())
    }

    fn set_value(&mut self, path: &str, name: &str, data: &ValueKind) -> Result<(), RegError> {
        self.set(path, name, data.clone());
        Ok(())
    }

    fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError> {
        let node = self.node(path).ok_or(RegError::NotFound)?;
        Ok(node
            .values
            .iter()
            .map(|(name, data)| RegValue {
                name: name.clone(),
                data: data.clone(),
            })
            .collect())
    }

    fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
        let node = self.node_mut(path).ok_or(RegError::NotFound)?;
        let key = node
            .values
            .keys()
            .find(|key| key.eq_ignore_ascii_case(name))
            .cloned()
            .ok_or(RegError::NotFound)?;
        node.values.remove(&key);
        Ok(())
    }

    fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
        let path = canonical_path(path);
        let mut parts: Vec<&str> = path.split('\\').collect();
        let Some(leaf) = parts.pop() else {
            return Err(RegError::Message("cannot delete a hive root".into()));
        };
        let parent = parts.join("\\");
        let parent_node = self.node_mut(&parent).ok_or(RegError::NotFound)?;
        let index = child_index(&parent_node.children, leaf).ok_or(RegError::NotFound)?;
        parent_node.children.remove(index);
        Ok(())
    }
}
