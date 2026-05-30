use super::*;

pub(super) fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

pub(super) fn join_ids(ids: &[Id]) -> String {
    ids.iter()
        .map(|id| id.0.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn join_strings(values: &[String]) -> String {
    values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",")
}
