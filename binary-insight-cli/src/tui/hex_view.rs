use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub struct HexViewer {
    pub scroll_offset: usize,
    pub bytes_per_row: usize,
}

impl HexViewer {
    pub fn new() -> Self {
        Self {
            scroll_offset: 0,
            bytes_per_row: 16,
        }
    }

    pub fn scroll_down(&mut self, total_bytes: usize) {
        if self.scroll_offset + self.bytes_per_row < total_bytes {
            self.scroll_offset += self.bytes_per_row;
        }
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset >= self.bytes_per_row {
            self.scroll_offset -= self.bytes_per_row;
        }
    }

    pub fn scroll_page_down(&mut self, total_bytes: usize, height: usize) {
        let rows = if height > 2 { height - 2 } else { 1 };
        let jump = rows * self.bytes_per_row;
        if self.scroll_offset + jump < total_bytes {
            self.scroll_offset += jump;
        } else {
            // go to max possible scroll
            // (simplified: just simple logic)
            if total_bytes > jump {
                self.scroll_offset = total_bytes - jump;
            }
        }
    }

    pub fn scroll_page_up(&mut self, height: usize) {
        let rows = if height > 2 { height - 2 } else { 1 };
        let jump = rows * self.bytes_per_row;
        if self.scroll_offset >= jump {
            self.scroll_offset -= jump;
        } else {
            self.scroll_offset = 0;
        }
    }

    pub fn draw(&self, f: &mut Frame, area: Rect, data: &[u8]) {
        if area.height < 3 {
            return;
        }
        let max_rows = (area.height as usize - 2).max(1);

        // Ensure scroll_offset is aligned logic or just simple chunks?
        // We render simple lines matching scroll offset.

        let start = self.scroll_offset;
        // Safety check if data changed or scroll is OOB
        if start >= data.len() && !data.is_empty() {
            // reset? or just empty
            // assuming caller handles or we just render nothing
        }

        let end = (start + max_rows * self.bytes_per_row).min(data.len());

        let mut lines = Vec::new();

        if start < data.len() {
            for (i, chunk) in data[start..end].chunks(self.bytes_per_row).enumerate() {
                let offset = start + i * self.bytes_per_row;

                // Hex part
                let mut hex_spans = Vec::new();
                for b in chunk {
                    hex_spans.push(format!("{:02x} ", b));
                }

                // Pad if incomplete row
                let padding_needed = self.bytes_per_row - chunk.len();
                let hex_string = hex_spans.join("");
                let padding = "   ".repeat(padding_needed); // 3 chars per byte "XX "

                // Ascii part
                let ascii_string: String = chunk
                    .iter()
                    .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                    .collect();

                let line = Line::from(vec![
                    Span::styled(
                        format!("{:08x}:  ", offset),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(hex_string, Style::default().fg(Color::White)),
                    Span::raw(padding),
                    Span::raw(" |"),
                    Span::styled(ascii_string, Style::default().fg(Color::Yellow)),
                    Span::raw("|"),
                ]);
                lines.push(line);
            }
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!("Hex View (Offset: 0x{:x})", start))
            .border_style(Style::default().fg(Color::Cyan));

        let paragraph = Paragraph::new(lines).block(block);
        f.render_widget(paragraph, area);
    }
}
