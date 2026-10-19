//! Batch execution dependency validation (#705)
//!
//! Validates that batch execution steps have proper dependencies and ordering.

#![no_std]

use soroban_sdk::{contracttype, Env, Vec};

/// Error codes for batch dependency validation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BatchDependencyError {
    /// A required dependency is missing.
    MissingDependency = 1,
    /// Circular dependency detected.
    CircularDependency = 2,
    /// A dependency is not yet completed.
    DependencyNotCompleted = 3,
    /// Invalid dependency reference.
    InvalidDependency = 4,
    /// The batch has no steps.
    EmptyBatch = 5,
    /// Dependency index is out of bounds.
    DependencyOutOfBounds = 6,
}

/// Status of a batch execution step.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StepStatus {
    /// Step is pending execution.
    Pending = 0,
    /// Step is currently executing.
    Executing = 1,
    /// Step completed successfully.
    Completed = 2,
    /// Step failed.
    Failed = 3,
    /// Step was skipped due to dependency failure.
    Skipped = 4,
}

/// A single step in a batch execution.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchStep {
    /// Unique step identifier.
    pub id: u32,
    /// Indices of steps that must complete before this one.
    pub dependencies: Vec<u32>,
    /// Current status of the step.
    pub status: StepStatus,
    /// Whether this step is critical (failure blocks dependent steps).
    pub is_critical: bool,
}

/// Validation result for a batch.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchValidationResult {
    /// Whether the batch is valid.
    pub is_valid: bool,
    /// Number of steps in the batch.
    pub step_count: u32,
    /// Number of dependencies validated.
    pub dependency_count: u32,
}

/// Validate that a batch has no circular dependencies using DFS.
pub fn validate_no_circular_dependencies(
    steps: &Vec<BatchStep>,
) -> Result<(), BatchDependencyError> {
    let n = steps.len() as u32;

    // visited: 0 = unvisited, 1 = visiting, 2 = visited
    let mut visited: Vec<u32> = Vec::new(&steps.env());
    for _ in 0..n {
        visited.push_back(0);
    }

    for i in 0..n {
        if visited.get(i).unwrap() == 0 {
            check_cycle(steps, &mut visited, i)?;
        }
    }

    Ok(())
}

fn check_cycle(
    steps: &Vec<BatchStep>,
    visited: &mut Vec<u32>,
    node: u32,
) -> Result<(), BatchDependencyError> {
    visited.set(node, 1); // Mark as visiting

    let step = steps.get(node).ok_or(BatchDependencyError::InvalidDependency)?;

    for dep_idx in step.dependencies.iter() {
        let dep = dep_idx;
        if dep >= steps.len() as u32 {
            return Err(BatchDependencyError::DependencyOutOfBounds);
        }

        let dep_status = visited.get(dep).unwrap();
        if dep_status == 1 {
            return Err(BatchDependencyError::CircularDependency);
        }
        if dep_status == 0 {
            check_cycle(steps, visited, dep)?;
        }
    }

    visited.set(node, 2); // Mark as visited
    Ok(())
}

/// Validate that all dependencies are within bounds.
pub fn validate_dependency_bounds(steps: &Vec<BatchStep>) -> Result<(), BatchDependencyError> {
    let n = steps.len() as u32;

    for step in steps.iter() {
        for dep in step.dependencies.iter() {
            if dep >= n {
                return Err(BatchDependencyError::DependencyOutOfBounds);
            }
            // A step cannot depend on itself
            if dep == step.id {
                return Err(BatchDependencyError::InvalidDependency);
            }
        }
    }

    Ok(())
}

/// Check if a step's dependencies are all completed.
pub fn are_dependencies_completed(
    steps: &Vec<BatchStep>,
    step_id: u32,
) -> Result<bool, BatchDependencyError> {
    let step = steps
        .iter()
        .find(|s| s.id == step_id)
        .ok_or(BatchDependencyError::InvalidDependency)?;

    for dep_id in step.dependencies.iter() {
        let dep_step = steps
            .iter()
            .find(|s| s.id == dep_id)
            .ok_or(BatchDependencyError::MissingDependency)?;

        if dep_step.status != StepStatus::Completed {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Validate a complete batch and return validation result.
pub fn validate_batch(steps: &Vec<BatchStep>) -> Result<BatchValidationResult, BatchDependencyError> {
    if steps.is_empty() {
        return Err(BatchDependencyError::EmptyBatch);
    }

    validate_dependency_bounds(steps)?;
    validate_no_circular_dependencies(steps)?;

    let mut dependency_count = 0u32;
    for step in steps.iter() {
        dependency_count += step.dependencies.len() as u32;
    }

    Ok(BatchValidationResult {
        is_valid: true,
        step_count: steps.len() as u32,
        dependency_count,
    })
}

/// Get the execution order using topological sort.
pub fn get_execution_order(steps: &Vec<BatchStep>) -> Result<Vec<u32>, BatchDependencyError> {
    let n = steps.len() as u32;
    let env = steps.env();

    // Calculate in-degrees
    let mut in_degree: Vec<u32> = Vec::new(&env);
    for _ in 0..n {
        in_degree.push_back(0);
    }

    for step in steps.iter() {
        for dep in step.dependencies.iter() {
            let current = in_degree.get(step.id).unwrap();
            in_degree.set(step.id, current + 1);
        }
    }

    // Find nodes with in-degree 0
    let mut queue: Vec<u32> = Vec::new(&env);
    for i in 0..n {
        if in_degree.get(i).unwrap() == 0 {
            queue.push_back(i);
        }
    }

    let mut order: Vec<u32> = Vec::new(&env);

    while !queue.is_empty() {
        let node = queue.pop_front().unwrap();
        order.push_back(node);

        // Reduce in-degree for dependents
        for step in steps.iter() {
            if step.dependencies.contains(&node) {
                let current = in_degree.get(step.id).unwrap();
                in_degree.set(step.id, current - 1);
                if current - 1 == 0 {
                    queue.push_back(step.id);
                }
            }
        }
    }

    if order.len() as u32 != n {
        return Err(BatchDependencyError::CircularDependency);
    }

    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, Vec};

    fn create_steps(env: &Env) -> Vec<BatchStep> {
        let mut steps = Vec::new(env);

        // Step 0: no dependencies
        let mut deps0 = Vec::new(env);
        steps.push_back(BatchStep {
            id: 0,
            dependencies: deps0,
            status: StepStatus::Pending,
            is_critical: true,
        });

        // Step 1: depends on 0
        let mut deps1 = Vec::new(env);
        deps1.push_back(0);
        steps.push_back(BatchStep {
            id: 1,
            dependencies: deps1,
            status: StepStatus::Pending,
            is_critical: true,
        });

        // Step 2: depends on 1
        let mut deps2 = Vec::new(env);
        deps2.push_back(1);
        steps.push_back(BatchStep {
            id: 2,
            dependencies: deps2,
            status: StepStatus::Pending,
            is_critical: false,
        });

        steps
    }

    #[test]
    fn test_validate_batch_valid() {
        let env = Env::default();
        let steps = create_steps(&env);

        let result = validate_batch(&steps);
        assert!(result.is_ok());
        assert!(result.unwrap().is_valid);
    }

    #[test]
    fn test_validate_empty_batch() {
        let env = Env::default();
        let steps: Vec<BatchStep> = Vec::new(&env);

        let result = validate_batch(&steps);
        assert_eq!(result, Err(BatchDependencyError::EmptyBatch));
    }

    #[test]
    fn test_circular_dependency() {
        let env = Env::default();
        let mut steps = Vec::new(&env);

        // Step 0 depends on 1
        let mut deps0 = Vec::new(&env);
        deps0.push_back(1);
        steps.push_back(BatchStep {
            id: 0,
            dependencies: deps0,
            status: StepStatus::Pending,
            is_critical: true,
        });

        // Step 1 depends on 0
        let mut deps1 = Vec::new(env);
        deps1.push_back(0);
        steps.push_back(BatchStep {
            id: 1,
            dependencies: deps1,
            status: StepStatus::Pending,
            is_critical: true,
        });

        let result = validate_no_circular_dependencies(&steps);
        assert_eq!(result, Err(BatchDependencyError::CircularDependency));
    }

    #[test]
    fn test_dependency_out_of_bounds() {
        let env = Env::default();
        let mut steps = Vec::new(&env);

        let mut deps0 = Vec::new(&env);
        deps0.push_back(5); // Invalid index
        steps.push_back(BatchStep {
            id: 0,
            dependencies: deps0,
            status: StepStatus::Pending,
            is_critical: true,
        });

        let result = validate_dependency_bounds(&steps);
        assert_eq!(result, Err(BatchDependencyError::DependencyOutOfBounds));
    }

    #[test]
    fn test_execution_order() {
        let env = Env::default();
        let steps = create_steps(&env);

        let order = get_execution_order(&steps);
        assert!(order.is_ok());

        let order = order.unwrap();
        assert_eq!(order.len(), 3);
        // Step 0 must come before step 1, which must come before step 2
        let pos0 = order.iter().position(|&x| x == 0).unwrap();
        let pos1 = order.iter().position(|&x| x == 1).unwrap();
        let pos2 = order.iter().position(|&x| x == 2).unwrap();
        assert!(pos0 < pos1);
        assert!(pos1 < pos2);
    }
}
