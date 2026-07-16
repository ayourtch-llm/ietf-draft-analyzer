/// Accumulates text extracted from structured documents while preserving
/// useful block boundaries and avoiding whitespace artifacts around inline
/// markup.
#[derive(Default)]
pub(crate) struct TextAccumulator {
    text: String,
}

impl TextAccumulator {
    pub(crate) fn push_inline(&mut self, value: &str) {
        let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.is_empty() {
            return;
        }

        let needs_space = self
            .text
            .chars()
            .next_back()
            .is_some_and(|last| !last.is_whitespace() && !is_opening_punctuation(last))
            && normalized
                .chars()
                .next()
                .is_some_and(|first| !is_closing_punctuation(first));
        if needs_space {
            self.text.push(' ');
        }
        self.text.push_str(&normalized);
    }

    pub(crate) fn push_preformatted(&mut self, value: &str) {
        let trimmed = value.trim_matches(['\r', '\n']);
        if trimmed.trim().is_empty() {
            return;
        }
        self.push_newline();
        for (index, line) in trimmed.lines().enumerate() {
            if index > 0 {
                self.text.push('\n');
            }
            self.text.push_str(line.trim_end());
        }
        self.push_newline();
    }

    pub(crate) fn push_newline(&mut self) {
        while self.text.ends_with(' ') || self.text.ends_with('\t') {
            self.text.pop();
        }
        if !self.text.is_empty() && !self.text.ends_with('\n') {
            self.text.push('\n');
        }
    }

    pub(crate) fn push_cell_separator(&mut self) {
        if self.text.is_empty() || self.text.ends_with('\n') {
            return;
        }
        if !self.text.ends_with(" | ") {
            self.text.push_str(" | ");
        }
    }

    pub(crate) fn finish(self) -> String {
        let mut output = String::new();
        let mut previous_blank = false;

        for line in self.text.lines() {
            let line = line.trim_end();
            if line.trim().is_empty() {
                if !previous_blank && !output.is_empty() {
                    output.push('\n');
                }
                previous_blank = true;
                continue;
            }
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(line.trim_end_matches(" |"));
            output.push('\n');
            previous_blank = false;
        }

        output.trim().to_string()
    }
}

fn is_opening_punctuation(c: char) -> bool {
    matches!(c, '(' | '[' | '{' | '/' | '-')
}

fn is_closing_punctuation(c: char) -> bool {
    matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_inline_markup_without_punctuation_artifacts() {
        let mut text = TextAccumulator::default();
        text.push_inline("A receiver");
        text.push_inline("MUST");
        text.push_inline("validate the field");
        text.push_inline(".");
        assert_eq!(text.finish(), "A receiver MUST validate the field.");
    }

    #[test]
    fn preserves_preformatted_blocks_and_table_rows() {
        let mut text = TextAccumulator::default();
        text.push_inline("Example:");
        text.push_preformatted("\npacket = 1OCTET\n  value = 1\n");
        text.push_inline("Value");
        text.push_cell_separator();
        text.push_inline("Meaning");
        text.push_newline();

        let output = text.finish();
        assert!(output.contains("packet = 1OCTET\n  value = 1"));
        assert!(output.contains("Value | Meaning"));
    }
}
