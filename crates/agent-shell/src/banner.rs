use crate::model::{VerifiedOpenShell, BANNER_TITLE};


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
        format!("session: {}", order.session_id),
        format!("agent: {}", printable(agent_id)),
        format!("asset: {}", order.asset),
        format!("ticket: {}", order.ticket),
        format!("requester: {}", order.requester),
        format!("approvers: {}", order.approvers.join(", ")),
    ];
    lines.iter().flat_map(|line| line.bytes().chain(BANNER_END_OF_LINE.bytes())).collect()
}
