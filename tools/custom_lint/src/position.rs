use crate::types::Position;


pub fn line_column(source: &str, offset: usize) -> Position {
    source.char_indices().take_while(|(index, _)| *index < offset).fold(
        (1, 1),
        |(line, column), (_, character)| {
            if character == '\n' {
                (line + 1, 1)
            } else {
                (line, column + 1)
            }
        },
    )
}
