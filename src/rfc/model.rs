use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for an RFC document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RfcNumber(pub u32);

impl fmt::Display for RfcNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RFC {}", self.0)
    }
}

impl From<u32> for RfcNumber {
    fn from(n: u32) -> Self {
        RfcNumber(n)
    }
}

/// The format the RFC was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfcFormat {
    Xml,
    PlainText,
}

impl fmt::Display for RfcFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RfcFormat::Xml => write!(f, "xml"),
            RfcFormat::PlainText => write!(f, "text"),
        }
    }
}

impl RfcFormat {
    /// Parse from the string stored in the database.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "xml" => Some(RfcFormat::Xml),
            "text" => Some(RfcFormat::PlainText),
            _ => None,
        }
    }
}

/// RFC publication status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RfcStatus {
    Standard,
    ProposedStandard,
    BestCurrentPractice,
    Informational,
    Experimental,
    Historic,
    Unknown,
}

impl fmt::Display for RfcStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            RfcStatus::Standard => "standard",
            RfcStatus::ProposedStandard => "proposed_standard",
            RfcStatus::BestCurrentPractice => "best_current_practice",
            RfcStatus::Informational => "informational",
            RfcStatus::Experimental => "experimental",
            RfcStatus::Historic => "historic",
            RfcStatus::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

impl RfcStatus {
    /// Parse from the string stored in the database or RFC metadata.
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "standard" | "internet standard" | "std" => RfcStatus::Standard,
            "proposed standard" | "proposed_standard" => RfcStatus::ProposedStandard,
            "best current practice" | "best_current_practice" | "bcp" => {
                RfcStatus::BestCurrentPractice
            }
            "informational" => RfcStatus::Informational,
            "experimental" => RfcStatus::Experimental,
            "historic" | "historical" => RfcStatus::Historic,
            _ => RfcStatus::Unknown,
        }
    }
}

/// A fully parsed RFC document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc {
    pub number: RfcNumber,
    pub title: String,
    pub format: RfcFormat,
    pub status: RfcStatus,
    pub date: NaiveDate,
    pub obsoletes: Vec<RfcNumber>,
    pub updates: Vec<RfcNumber>,
    pub obsoleted_by: Vec<RfcNumber>,
    pub updated_by: Vec<RfcNumber>,
    pub sections: Vec<Section>,
    pub references: Vec<Reference>,
    pub raw_text: String,
    pub content_hash: String,
}

/// A section within an RFC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub number: String,
    pub title: String,
    pub anchor: Option<String>,
    pub depth: u8,
    pub text: String,
    pub cross_refs: Vec<CrossRef>,
    pub pn: Option<String>,
}

/// A cross-reference found inline in section text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossRef {
    pub target_rfc: Option<RfcNumber>,
    pub target_section: Option<String>,
    pub context: String,
}

/// An entry from the References section of the RFC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    pub label: String,
    pub target_rfc: Option<RfcNumber>,
    pub title: String,
    pub is_normative: bool,
}
