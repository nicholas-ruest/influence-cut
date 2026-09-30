#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphDocument {
    pub schema_version: u32,
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub tenant: String,
    pub sequence: u64,
    pub kind: NodeKind,
    #[serde(default)]
    pub parents: Vec<String>,
    pub repair: RepairMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Source,
    Summary,
    Embedding,
    Index,
    Plan,
    ToolObservation,
    ToolEffect,
    Checkpoint,
    Receipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairMode {
    Invalidate,
    Rebuild,
    Replay,
    Compensate,
    Unavailable,
    Preserve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub tenant: String,
    pub target_ids: Vec<String>,
    #[serde(default)]
    pub preserve_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairPlan {
    pub schema_version: u32,
    pub request_id: String,
    pub tenant: String,
    pub target_ids: Vec<String>,
    pub affected_ids: Vec<String>,
    pub clean_checkpoint: Option<String>,
    pub invalidations: Vec<PlanStep>,
    pub reconstructions: Vec<PlanStep>,
    pub blockers: Vec<Blocker>,
    pub executable: bool,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub node_id: String,
    pub sequence: u64,
    pub action: PlanAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    Invalidate,
    Rebuild,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blocker {
    pub node_id: String,
    pub code: BlockerCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerCode {
    CommittedEffect,
    PreserveConflict,
    UnavailableState,
    MissingCheckpoint,
    CompensationRequired,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("unsupported {document} schema version {actual}; expected {expected}")]
    SchemaVersion {
        document: &'static str,
        actual: u32,
        expected: u32,
    },
    #[error("{field} must not be empty")]
    EmptyField { field: String },
    #[error("duplicate node id: {0}")]
    DuplicateNode(String),
    #[error("duplicate id in {field}: {id}")]
    DuplicateListId { field: &'static str, id: String },
    #[error("node {node} references missing parent {parent}")]
    MissingParent { node: String, parent: String },
    #[error("node {node} in tenant {tenant} references parent {parent} in tenant {parent_tenant}")]
    CrossTenantEdge {
        node: String,
        tenant: String,
        parent: String,
        parent_tenant: String,
    },
    #[error(
        "node {node} at sequence {sequence} must come after parent {parent} at sequence {parent_sequence}"
    )]
    NonMonotonicEdge {
        node: String,
        sequence: u64,
        parent: String,
        parent_sequence: u64,
    },
    #[error("source node {0} must not have parents")]
    SourceHasParents(String),
    #[error("derived node {0} must have at least one parent")]
    DerivedWithoutParent(String),
    #[error("request references missing node: {0}")]
    MissingRequestNode(String),
    #[error("request node {node} belongs to tenant {actual}, not {expected}")]
    RequestTenantMismatch {
        node: String,
        actual: String,
        expected: String,
    },
}

/// Validates graph structure, tenant isolation, and monotonic provenance edges.
///
/// # Errors
///
/// Returns [`ValidationError`] when the schema is unsupported or a graph
/// invariant is violated.
pub fn validate_graph(graph: &GraphDocument) -> Result<(), ValidationError> {
    if graph.schema_version != SCHEMA_VERSION {
        return Err(ValidationError::SchemaVersion {
            document: "graph",
            actual: graph.schema_version,
            expected: SCHEMA_VERSION,
        });
    }

    let mut by_id = BTreeMap::new();
    for node in &graph.nodes {
        require_text(&node.id, format!("nodes[{}].id", node.sequence))?;
        require_text(&node.tenant, format!("nodes[{}].tenant", node.id))?;
        if by_id.insert(node.id.as_str(), node).is_some() {
            return Err(ValidationError::DuplicateNode(node.id.clone()));
        }
        if node.kind == NodeKind::Source && !node.parents.is_empty() {
            return Err(ValidationError::SourceHasParents(node.id.clone()));
        }
        if node.kind != NodeKind::Source
            && node.kind != NodeKind::Checkpoint
            && node.parents.is_empty()
        {
            return Err(ValidationError::DerivedWithoutParent(node.id.clone()));
        }
        ensure_unique(&node.parents, "node.parents")?;
    }

    for node in &graph.nodes {
        for parent_id in &node.parents {
            let parent =
                by_id
                    .get(parent_id.as_str())
                    .ok_or_else(|| ValidationError::MissingParent {
                        node: node.id.clone(),
                        parent: parent_id.clone(),
                    })?;
            if node.tenant != parent.tenant {
                return Err(ValidationError::CrossTenantEdge {
                    node: node.id.clone(),
                    tenant: node.tenant.clone(),
                    parent: parent.id.clone(),
                    parent_tenant: parent.tenant.clone(),
                });
            }
            if parent.sequence >= node.sequence {
                return Err(ValidationError::NonMonotonicEdge {
                    node: node.id.clone(),
                    sequence: node.sequence,
                    parent: parent.id.clone(),
                    parent_sequence: parent.sequence,
                });
            }
        }
    }
    Ok(())
}

/// Validates request identity, node existence, uniqueness, and tenant scope.
///
/// # Errors
///
/// Returns [`ValidationError`] when the request is malformed or references a
/// node outside the validated graph and tenant.
pub fn validate_request(
    graph: &GraphDocument,
    request: &RevocationRequest,
) -> Result<(), ValidationError> {
    if request.schema_version != SCHEMA_VERSION {
        return Err(ValidationError::SchemaVersion {
            document: "request",
            actual: request.schema_version,
            expected: SCHEMA_VERSION,
        });
    }
    require_text(&request.request_id, "request_id".to_owned())?;
    require_text(&request.tenant, "tenant".to_owned())?;
    if request.target_ids.is_empty() {
        return Err(ValidationError::EmptyField {
            field: "target_ids".to_owned(),
        });
    }
    ensure_unique(&request.target_ids, "target_ids")?;
    ensure_unique(&request.preserve_ids, "preserve_ids")?;

    let by_id: BTreeMap<_, _> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    for id in request.target_ids.iter().chain(&request.preserve_ids) {
        let node = by_id
            .get(id.as_str())
            .ok_or_else(|| ValidationError::MissingRequestNode(id.clone()))?;
        if node.tenant != request.tenant {
            return Err(ValidationError::RequestTenantMismatch {
                node: id.clone(),
                actual: node.tenant.clone(),
                expected: request.tenant.clone(),
            });
        }
    }
    Ok(())
}

/// Builds a deterministic repair plan for the request's descendant closure.
///
/// # Errors
///
/// Returns [`ValidationError`] when either input document violates its schema
/// or provenance invariants.
#[allow(clippy::too_many_lines)] // One classification pass keeps every repair mode visibly fail-closed.
pub fn build_plan(
    graph: &GraphDocument,
    request: &RevocationRequest,
) -> Result<RepairPlan, ValidationError> {
    validate_graph(graph)?;
    validate_request(graph, request)?;

    let by_id: BTreeMap<_, _> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in &graph.nodes {
        for parent in &node.parents {
            children
                .entry(parent.as_str())
                .or_default()
                .push(node.id.as_str());
        }
    }

    let mut affected = BTreeSet::new();
    let mut queue: VecDeque<&str> = request.target_ids.iter().map(String::as_str).collect();
    while let Some(id) = queue.pop_front() {
        if affected.insert(id) {
            if let Some(node_children) = children.get(id) {
                queue.extend(node_children.iter().copied());
            }
        }
    }

    let first_target_sequence = request
        .target_ids
        .iter()
        .filter_map(|id| by_id.get(id.as_str()).map(|node| node.sequence))
        .min()
        .ok_or_else(|| ValidationError::EmptyField {
            field: "target_ids".to_owned(),
        })?;
    let clean_checkpoint = graph
        .nodes
        .iter()
        .filter(|node| {
            node.tenant == request.tenant
                && node.kind == NodeKind::Checkpoint
                && node.sequence < first_target_sequence
                && !affected.contains(node.id.as_str())
        })
        .max_by_key(|node| (node.sequence, node.id.as_str()))
        .map(|node| node.id.clone());

    let explicit_preserve: BTreeSet<&str> =
        request.preserve_ids.iter().map(String::as_str).collect();
    let mut invalidations = Vec::new();
    let mut reconstructions = Vec::new();
    let mut blockers = Vec::new();
    let mut needs_checkpoint = false;

    for id in &affected {
        let node = by_id[id];
        let preserved = explicit_preserve.contains(id) || node.repair == RepairMode::Preserve;
        if preserved {
            blockers.push(Blocker {
                node_id: node.id.clone(),
                code: BlockerCode::PreserveConflict,
                message: "affected state is marked for preservation".to_owned(),
            });
            continue;
        }
        if node.kind == NodeKind::ToolEffect {
            blockers.push(Blocker {
                node_id: node.id.clone(),
                code: BlockerCode::CommittedEffect,
                message: "committed tool effects cannot be erased by state repair".to_owned(),
            });
            continue;
        }
        match node.repair {
            RepairMode::Unavailable => blockers.push(Blocker {
                node_id: node.id.clone(),
                code: BlockerCode::UnavailableState,
                message: "state is outside the planner's repair boundary".to_owned(),
            }),
            RepairMode::Compensate => blockers.push(Blocker {
                node_id: node.id.clone(),
                code: BlockerCode::CompensationRequired,
                message: "a separately authorized compensation is required".to_owned(),
            }),
            RepairMode::Invalidate => invalidations.push(step(node, PlanAction::Invalidate)),
            RepairMode::Rebuild => {
                invalidations.push(step(node, PlanAction::Invalidate));
                reconstructions.push(step(node, PlanAction::Rebuild));
            }
            RepairMode::Replay => {
                needs_checkpoint = true;
                invalidations.push(step(node, PlanAction::Invalidate));
                reconstructions.push(step(node, PlanAction::Replay));
            }
            RepairMode::Preserve => unreachable!("preserve was handled above"),
        }
    }

    if needs_checkpoint && clean_checkpoint.is_none() {
        blockers.push(Blocker {
            node_id: "<request>".to_owned(),
            code: BlockerCode::MissingCheckpoint,
            message: "replay is required but no clean checkpoint precedes every target".to_owned(),
        });
    }

    invalidations.sort_by(|left, right| {
        right
            .sequence
            .cmp(&left.sequence)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    reconstructions.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    blockers.sort_by(|left, right| {
        left.node_id
            .cmp(&right.node_id)
            .then_with(|| left.code.cmp(&right.code))
    });

    let mut target_ids = request.target_ids.clone();
    target_ids.sort();
    let affected_ids = affected.into_iter().map(str::to_owned).collect();
    let mut plan = RepairPlan {
        schema_version: SCHEMA_VERSION,
        request_id: request.request_id.clone(),
        tenant: request.tenant.clone(),
        target_ids,
        affected_ids,
        clean_checkpoint,
        invalidations,
        reconstructions,
        executable: blockers.is_empty(),
        blockers,
        digest: String::new(),
    };
    plan.digest = calculate_digest(&plan);
    Ok(plan)
}

#[must_use]
pub fn verify_plan_digest(plan: &RepairPlan) -> bool {
    plan.digest == calculate_digest(plan)
}

#[must_use]
pub fn render_human(plan: &RepairPlan) -> String {
    let status = if plan.executable { "READY" } else { "BLOCKED" };
    let checkpoint = plan.clean_checkpoint.as_deref().unwrap_or("none");
    let mut output = format!(
        "{status} request={} tenant={} affected={} checkpoint={}\n",
        plan.request_id,
        plan.tenant,
        plan.affected_ids.len(),
        checkpoint
    );
    for step in &plan.invalidations {
        let _ = writeln!(
            output,
            "  invalidate seq={} node={}",
            step.sequence, step.node_id
        );
    }
    for step in &plan.reconstructions {
        let action = match step.action {
            PlanAction::Rebuild => "rebuild",
            PlanAction::Replay => "replay",
            PlanAction::Invalidate => "invalidate",
        };
        let _ = writeln!(
            output,
            "  {action} seq={} node={}",
            step.sequence, step.node_id
        );
    }
    for blocker in &plan.blockers {
        let _ = writeln!(
            output,
            "  blocker code={} node={}: {}",
            blocker_code_name(blocker.code),
            blocker.node_id,
            blocker.message
        );
    }
    let _ = writeln!(output, "digest={}", plan.digest);
    output
}

const fn blocker_code_name(code: BlockerCode) -> &'static str {
    match code {
        BlockerCode::CommittedEffect => "committed_effect",
        BlockerCode::PreserveConflict => "preserve_conflict",
        BlockerCode::UnavailableState => "unavailable_state",
        BlockerCode::MissingCheckpoint => "missing_checkpoint",
        BlockerCode::CompensationRequired => "compensation_required",
    }
}

fn require_text(value: &str, field: String) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::EmptyField { field });
    }
    Ok(())
}

fn ensure_unique(values: &[String], field: &'static str) -> Result<(), ValidationError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.as_str()) {
            return Err(ValidationError::DuplicateListId {
                field,
                id: value.clone(),
            });
        }
    }
    Ok(())
}

fn step(node: &Node, action: PlanAction) -> PlanStep {
    PlanStep {
        node_id: node.id.clone(),
        sequence: node.sequence,
        action,
    }
}

fn calculate_digest(plan: &RepairPlan) -> String {
    let mut unsigned = plan.clone();
    unsigned.digest.clear();
    let bytes = serde_json::to_vec(&unsigned).expect("repair plan serialization cannot fail");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, sequence: u64, kind: NodeKind, parents: &[&str], repair: RepairMode) -> Node {
        Node {
            id: id.to_owned(),
            tenant: "acme".to_owned(),
            sequence,
            kind,
            parents: parents.iter().map(|value| (*value).to_owned()).collect(),
            repair,
        }
    }

    fn graph() -> GraphDocument {
        GraphDocument {
            schema_version: 1,
            nodes: vec![
                node("cp-0", 1, NodeKind::Checkpoint, &[], RepairMode::Preserve),
                node("source-a", 2, NodeKind::Source, &[], RepairMode::Invalidate),
                node(
                    "summary-a",
                    3,
                    NodeKind::Summary,
                    &["source-a"],
                    RepairMode::Rebuild,
                ),
                node(
                    "plan-a",
                    4,
                    NodeKind::Plan,
                    &["summary-a"],
                    RepairMode::Replay,
                ),
                node("source-b", 5, NodeKind::Source, &[], RepairMode::Invalidate),
                node(
                    "summary-b",
                    6,
                    NodeKind::Summary,
                    &["source-b"],
                    RepairMode::Rebuild,
                ),
            ],
        }
    }

    fn request() -> RevocationRequest {
        RevocationRequest {
            schema_version: 1,
            request_id: "rev-42".to_owned(),
            tenant: "acme".to_owned(),
            target_ids: vec!["source-a".to_owned()],
            preserve_ids: Vec::new(),
        }
    }

    #[test]
    fn plans_only_the_descendant_closure() {
        let plan = build_plan(&graph(), &request()).unwrap();
        assert!(plan.executable);
        assert_eq!(plan.affected_ids, ["plan-a", "source-a", "summary-a"]);
        assert_eq!(plan.clean_checkpoint.as_deref(), Some("cp-0"));
        assert_eq!(plan.invalidations[0].node_id, "plan-a");
        assert_eq!(plan.invalidations[2].node_id, "source-a");
        assert_eq!(plan.reconstructions[0].node_id, "summary-a");
        assert_eq!(plan.reconstructions[1].node_id, "plan-a");
        assert!(verify_plan_digest(&plan));
    }

    #[test]
    fn digest_is_independent_of_input_node_order() {
        let first = build_plan(&graph(), &request()).unwrap();
        let mut reordered = graph();
        reordered.nodes.reverse();
        let second = build_plan(&reordered, &request()).unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(first, second);
    }

    #[test]
    fn changed_plan_fails_digest_verification() {
        let mut plan = build_plan(&graph(), &request()).unwrap();
        plan.request_id = "tampered".to_owned();
        assert!(!verify_plan_digest(&plan));
    }

    #[test]
    fn preserve_conflicts_block_execution() {
        let mut request = request();
        request.preserve_ids.push("summary-a".to_owned());
        let plan = build_plan(&graph(), &request).unwrap();
        assert!(!plan.executable);
        assert_eq!(plan.blockers[0].code, BlockerCode::PreserveConflict);
    }

    #[test]
    fn committed_tool_effects_are_never_treated_as_erasable_state() {
        let mut graph = graph();
        graph.nodes.push(node(
            "email-sent",
            7,
            NodeKind::ToolEffect,
            &["plan-a"],
            RepairMode::Compensate,
        ));
        let plan = build_plan(&graph, &request()).unwrap();
        assert!(!plan.executable);
        assert_eq!(plan.blockers[0].code, BlockerCode::CommittedEffect);
    }

    #[test]
    fn unavailable_state_is_reported() {
        let mut graph = graph();
        graph.nodes.push(node(
            "vendor-cache",
            7,
            NodeKind::Index,
            &["summary-a"],
            RepairMode::Unavailable,
        ));
        let plan = build_plan(&graph, &request()).unwrap();
        assert_eq!(plan.blockers[0].code, BlockerCode::UnavailableState);
    }

    #[test]
    fn replay_without_a_prior_checkpoint_is_blocked() {
        let mut graph = graph();
        graph.nodes.retain(|node| node.kind != NodeKind::Checkpoint);
        let plan = build_plan(&graph, &request()).unwrap();
        assert!(
            plan.blockers
                .iter()
                .any(|blocker| blocker.code == BlockerCode::MissingCheckpoint)
        );
    }

    #[test]
    fn cross_tenant_edges_are_rejected() {
        let mut graph = graph();
        graph.nodes[2].tenant = "other".to_owned();
        assert!(matches!(
            validate_graph(&graph),
            Err(ValidationError::CrossTenantEdge { .. })
        ));
    }

    #[test]
    fn non_monotonic_edges_are_rejected() {
        let mut graph = graph();
        graph.nodes[2].sequence = 2;
        assert!(matches!(
            validate_graph(&graph),
            Err(ValidationError::NonMonotonicEdge { .. })
        ));
    }

    #[test]
    fn request_tenant_mismatch_is_rejected() {
        let mut request = request();
        request.tenant = "other".to_owned();
        assert!(matches!(
            validate_request(&graph(), &request),
            Err(ValidationError::RequestTenantMismatch { .. })
        ));
    }
}
