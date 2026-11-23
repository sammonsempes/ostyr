use crate::model::{approvers_of, asset_of, requester_of, session_id_of, ticket_of, VerifiedOpenShell, BANNER_TITLE};


pub const BANNER_END_OF_LINE: &str = "\r\n";


pub const REPLACEMENT: char = '?';


/// Printable ASCII only: a configured name can never write a terminal escape into the operator stream.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                REPLACEMENT
            }
        })
        .collect()
}


/// The first bytes of the operator stream and of its recording: the session as signed, and the agent's own configured identity.
pub fn shell_banner(order: &VerifiedOpenShell, agent_id: &str) -> Vec<u8> {
    let lines = [
        BANNER_TITLE.to_owned(),
        format!("session: {}", session_id_of(order)),
        format!("agent: {}", printable(agent_id)),
        format!("asset: {}", asset_of(order)),
        format!("ticket: {}", ticket_of(order)),
        format!("requester: {}", requester_of(order)),
        format!("approvers: {}", approvers_of(order).join(", ")),
    ];
    lines.iter().flat_map(|line| line.bytes().chain(BANNER_END_OF_LINE.bytes())).collect()
}
