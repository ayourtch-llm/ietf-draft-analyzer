use crate::rfc::model::{RfcNumber, RfcStatus};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A node in the RFC dependency graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfcNode {
    pub rfc: RfcNumber,
    pub title: String,
    pub status: RfcStatus,
}

/// Edge direction: source → target.
/// Source is the document containing the reference.
/// Target is the document being referenced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepEdge {
    pub kind: EdgeKind,
    /// Section in the source RFC (for CrossReference edges).
    pub source_section: Option<String>,
    /// Section in the target RFC (for CrossReference edges).
    pub target_section: Option<String>,
}

/// The kind of dependency between two RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// RFC A obsoletes RFC B (A is newer, replaces B).
    Obsoletes,
    /// RFC A updates RFC B (A modifies/extends B).
    Updates,
    /// RFC A normatively references RFC B.
    NormativeReference,
    /// RFC A informatively references RFC B.
    InformativeReference,
    /// Section in RFC A references section in RFC B.
    CrossReference,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdgeKind::Obsoletes => write!(f, "obsoletes"),
            EdgeKind::Updates => write!(f, "updates"),
            EdgeKind::NormativeReference => write!(f, "normative_ref"),
            EdgeKind::InformativeReference => write!(f, "informative_ref"),
            EdgeKind::CrossReference => write!(f, "cross_ref"),
        }
    }
}

impl EdgeKind {
    /// Parse from the string stored in the database.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "obsoletes" => Some(EdgeKind::Obsoletes),
            "updates" => Some(EdgeKind::Updates),
            "normative_ref" => Some(EdgeKind::NormativeReference),
            "informative_ref" => Some(EdgeKind::InformativeReference),
            "cross_ref" => Some(EdgeKind::CrossReference),
            _ => None,
        }
    }
}
