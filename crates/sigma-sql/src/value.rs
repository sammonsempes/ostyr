use crate::sql::like_escape;


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Literal(char),
    Many,
    One,
}


const ESCAPE_PAIR: usize = 2;


fn literals(piece: char, count: usize) -> Vec<Piece> {
    vec![Piece::Literal(piece); count]
}


fn wildcard(escaped: bool, character: char) -> Piece {
    match (escaped, character) {
        (true, literal) => Piece::Literal(literal),
        (false, '*') => Piece::Many,
        (false, _) => Piece::One,
    }
}


fn step((mut pieces, backslashes): (Vec<Piece>, usize), character: char) -> (Vec<Piece>, usize) {
    match character {
        '\\' => (pieces, backslashes + 1),
        '*' | '?' => {
            pieces.extend(literals('\\', backslashes / ESCAPE_PAIR));
            pieces.push(wildcard(backslashes % ESCAPE_PAIR == 1, character));
            (pieces, 0)
        }
        other => {
            pieces.extend(literals('\\', backslashes));
            pieces.push(Piece::Literal(other));
            (pieces, 0)
        }
    }
}


/// Splits a Sigma value into literals and wildcards: `*` and `?` are wildcards, an odd backslash run escapes them and pairs collapse before them.
pub fn parse_pieces(text: &str) -> Vec<Piece> {
    let (mut pieces, trailing) = text.chars().fold((Vec::new(), 0), step);
    pieces.extend(literals('\\', trailing));
    pieces
}


fn piece_pattern(piece: &Piece) -> String {
    match piece {
        Piece::Literal(character) => like_escape(*character),
        Piece::Many => "%".to_string(),
        Piece::One => "_".to_string(),
    }
}


/// Builds the unescaped `LIKE` pattern text for the pieces, optionally open at either end.
pub fn like_pattern(pieces: &[Piece], open_start: bool, open_end: bool) -> String {
    let body: String = pieces.iter().map(piece_pattern).collect();
    let start = if open_start { "%" } else { "" };
    let end = if open_end { "%" } else { "" };
    format!("{start}{body}{end}")
}
