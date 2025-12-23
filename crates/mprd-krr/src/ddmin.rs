//! Delta debugging (ddmin) algorithm for subset minimization.
//!
//! Used to find minimal supports for derived facts.

use std::collections::HashSet;
use std::hash::Hash;

/// Oracle function type: returns true if the subset satisfies the property.
pub trait Oracle<T> {
    fn test(&self, subset: &[T]) -> bool;
}

impl<T, F> Oracle<T> for F
where
    F: Fn(&[T]) -> bool,
{
    fn test(&self, subset: &[T]) -> bool {
        (self)(subset)
    }
}

/// Delta debugging algorithm for finding minimal subsets.
///
/// Given a set of elements and an oracle that tests whether a subset
/// satisfies some property, returns a subset-minimal set that still
/// satisfies the property.
///
/// # Arguments
/// * `elements` - The initial set of elements
/// * `oracle` - Function that returns true if the subset satisfies the property
///
/// # Returns
/// A subset-minimal set such that:
/// - oracle(result) == true
/// - For all proper subsets S of result: oracle(S) == false
pub fn ddmin<T, O>(elements: &[T], oracle: &O) -> Vec<T>
where
    T: Clone + Eq + Hash,
    O: Oracle<T>,
{
    // Check if empty set works
    if elements.is_empty() || oracle.test(&[]) {
        return Vec::new();
    }
    
    // Check if full set works
    if !oracle.test(elements) {
        return Vec::new();
    }
    
    let mut current: Vec<T> = elements.to_vec();
    let mut n = 2;
    
    while current.len() >= 2 {
        let chunk_size = (current.len() + n - 1) / n; // Ceiling division
        let chunks: Vec<Vec<T>> = current
            .chunks(chunk_size)
            .map(|c| c.to_vec())
            .collect();
        
        let mut reduced = false;
        
        // Try removing each chunk (complement test)
        for (i, _chunk) in chunks.iter().enumerate() {
            let complement: Vec<T> = chunks
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .flat_map(|(_, c)| c.iter().cloned())
                .collect();
            
            if !complement.is_empty() && oracle.test(&complement) {
                current = complement;
                n = n.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
        }
        
        if reduced {
            continue;
        }
        
        // Try each chunk alone
        for chunk in &chunks {
            if chunk.len() < current.len() && oracle.test(chunk) {
                current = chunk.clone();
                n = 2;
                reduced = true;
                break;
            }
        }
        
        if reduced {
            continue;
        }
        
        // Increase granularity
        if n >= current.len() {
            break;
        }
        n = (n * 2).min(current.len());
    }
    
    current
}

/// Cached oracle wrapper to avoid redundant oracle calls.
pub struct CachedOracle<T, O>
where
    T: Clone + Eq + Hash + Ord,
    O: Oracle<T>,
{
    inner: O,
    cache: std::cell::RefCell<HashSet<Vec<T>>>,
}

impl<T, O> CachedOracle<T, O>
where
    T: Clone + Eq + Hash + Ord,
    O: Oracle<T>,
{
    pub fn new(oracle: O) -> Self {
        CachedOracle {
            inner: oracle,
            cache: std::cell::RefCell::new(HashSet::new()),
        }
    }
    
    pub fn cache_hits(&self) -> usize {
        self.cache.borrow().len()
    }
}

impl<T, O> Oracle<T> for CachedOracle<T, O>
where
    T: Clone + Eq + Hash + Ord,
    O: Oracle<T>,
{
    fn test(&self, subset: &[T]) -> bool {
        let mut sorted: Vec<T> = subset.to_vec();
        sorted.sort();
        
        if self.cache.borrow().contains(&sorted) {
            return true; // Cached as passing
        }
        
        let result = self.inner.test(subset);
        if result {
            self.cache.borrow_mut().insert(sorted);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ddmin_simple() {
        // Elements: [1, 2, 3, 4, 5]
        // Property: contains 2 AND 4
        let elements = vec![1, 2, 3, 4, 5];
        let oracle = |subset: &[i32]| subset.contains(&2) && subset.contains(&4);
        
        let result = ddmin(&elements, &oracle);
        
        assert!(oracle(&result));
        assert!(result.contains(&2));
        assert!(result.contains(&4));
        // Should be minimal: exactly {2, 4}
        assert_eq!(result.len(), 2);
    }
    
    #[test]
    fn test_ddmin_single_element() {
        let elements = vec![1, 2, 3];
        let oracle = |subset: &[i32]| subset.contains(&2);
        
        let result = ddmin(&elements, &oracle);
        
        assert_eq!(result, vec![2]);
    }
    
    #[test]
    fn test_ddmin_all_required() {
        let elements = vec![1, 2, 3];
        let oracle = |subset: &[i32]| {
            subset.contains(&1) && subset.contains(&2) && subset.contains(&3)
        };
        
        let result = ddmin(&elements, &oracle);
        
        assert_eq!(result.len(), 3);
    }
    
    #[test]
    fn test_ddmin_empty_works() {
        let elements = vec![1, 2, 3];
        let oracle = |_subset: &[i32]| true; // Always passes
        
        let result = ddmin(&elements, &oracle);
        
        assert!(result.is_empty());
    }
}
