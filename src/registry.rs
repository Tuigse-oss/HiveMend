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
    /// Start a transaction. A registry that cannot offer one says so, and
    /// callers that need one leave their work undone (scan-only).
    fn begin(&mut self) -> Result<Box<dyn RegTransaction + '_>, RegError> {
        Err(RegError::Message(
            "registry transactions are not available".into(),
        ))
    }
}

/// A registry transaction. Its reads see its own changes; nothing it writes
/// is visible to anything else until [`commit`](RegTransaction::commit).
/// Once a key has been written in it ([`touch`](RegTransaction::touch)),
/// any change to that key from outside makes the commit fail, so nothing
/// is applied. Dropping it uncommitted rolls everything back.
pub trait RegTransaction: Registry {
    /// Write to `key` inside the transaction (and undo the write), so a
    /// change to it from anywhere else before commit aborts the commit.
    fn touch(&mut self, key: &str) -> Result<(), RegError>;
    fn commit(self: Box<Self>) -> Result<(), RegError>;
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
    /// Test hook: keys "another program" changes while a transaction is
    /// open. A commit that touched any of them fails, as on Windows.
    pub changed_elsewhere: Vec<String>,
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

    fn begin(&mut self) -> Result<Box<dyn RegTransaction + '_>, RegError> {
        let work = self.clone();
        Ok(Box::new(MemoryTransaction {
            base: self,
            work,
            touched: Vec::new(),
        }))
    }
}

/// A transaction over a [`MemoryRegistry`]: changes go to a copy that
/// replaces the original on commit.
struct MemoryTransaction<'a> {
    base: &'a mut MemoryRegistry,
    work: MemoryRegistry,
    touched: Vec<String>,
}

impl Registry for MemoryTransaction<'_> {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
        self.work.subkeys(path)
    }
    fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError> {
        self.work.values(path)
    }
    fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
        self.work.delete_value(path, name)
    }
    fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
        self.work.delete_tree(path)
    }
    fn set_value(&mut self, path: &str, name: &str, data: &ValueKind) -> Result<(), RegError> {
        self.work.set_value(path, name, data)
    }
}

impl RegTransaction for MemoryTransaction<'_> {
    fn touch(&mut self, key: &str) -> Result<(), RegError> {
        self.work.node(key).ok_or(RegError::NotFound)?;
        self.touched.push(canonical_path(key));
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), RegError> {
        let conflict = self.touched.iter().any(|touched| {
            self.base
                .changed_elsewhere
                .iter()
                .any(|changed| canonical_path(changed).eq_ignore_ascii_case(touched))
        });
        if conflict {
            return Err(RegError::Message(
                "another program changed it during the transaction".into(),
            ));
        }
        let changed = std::mem::take(&mut self.base.changed_elsewhere);
        *self.base = self.work;
        self.base.changed_elsewhere = changed;
        Ok(())
    }
}

/// Test helper: a transaction that refuses to read one key, as a locked-down
/// ACL would, wrapped around another transaction.
#[cfg(test)]
pub(crate) struct DenyTx<'a> {
    pub inner: Box<dyn RegTransaction + 'a>,
    pub deny_subkeys: Option<String>,
    pub deny_values: Option<String>,
    pub deny_writes: Option<String>,
}

#[cfg(test)]
impl DenyTx<'_> {
    fn denied(rule: &Option<String>, path: &str) -> bool {
        rule.as_ref()
            .is_some_and(|locked| canonical_path(path).eq_ignore_ascii_case(locked))
    }
}

#[cfg(test)]
impl Registry for DenyTx<'_> {
    fn subkeys(&self, path: &str) -> Result<Vec<String>, RegError> {
        if Self::denied(&self.deny_subkeys, path) {
            return Err(RegError::Denied("access denied".into()));
        }
        self.inner.subkeys(path)
    }
    fn values(&self, path: &str) -> Result<Vec<RegValue>, RegError> {
        if Self::denied(&self.deny_values, path) {
            return Err(RegError::Denied("access denied".into()));
        }
        self.inner.values(path)
    }
    fn delete_value(&mut self, path: &str, name: &str) -> Result<(), RegError> {
        if Self::denied(&self.deny_writes, path) {
            return Err(RegError::Denied("access denied".into()));
        }
        self.inner.delete_value(path, name)
    }
    fn delete_tree(&mut self, path: &str) -> Result<(), RegError> {
        if Self::denied(&self.deny_writes, path) {
            return Err(RegError::Denied("access denied".into()));
        }
        self.inner.delete_tree(path)
    }
    fn set_value(&mut self, path: &str, name: &str, data: &ValueKind) -> Result<(), RegError> {
        if Self::denied(&self.deny_writes, path) {
            return Err(RegError::Denied("access denied".into()));
        }
        self.inner.set_value(path, name, data)
    }
}

#[cfg(test)]
impl RegTransaction for DenyTx<'_> {
    fn touch(&mut self, key: &str) -> Result<(), RegError> {
        self.inner.touch(key)
    }
    fn commit(self: Box<Self>) -> Result<(), RegError> {
        self.inner.commit()
    }
}
