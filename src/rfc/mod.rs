pub mod encoding;
pub mod fetcher;
pub mod index;
pub mod model;
pub mod parser_html;
pub mod parser_text;
pub mod parser_xml;
pub(crate) mod text;

use model::RfcFormat;

pub const XML_PARSER_VERSION: &str = "2";
pub const TEXT_PARSER_VERSION: &str = "2";
pub const HTML_PARSER_VERSION: &str = "1";

pub fn parser_version(format: RfcFormat) -> &'static str {
    match format {
        RfcFormat::Xml => XML_PARSER_VERSION,
        RfcFormat::PlainText => TEXT_PARSER_VERSION,
        RfcFormat::Html => HTML_PARSER_VERSION,
    }
}

pub fn parser_version_for_db_format(format: &str) -> Option<&'static str> {
    RfcFormat::from_db_str(format).map(parser_version)
}
