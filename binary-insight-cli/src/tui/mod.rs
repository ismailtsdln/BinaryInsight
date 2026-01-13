use anyhow::Result;
use binary_insight_core::binary::BinaryFile;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs},
    Frame, Terminal,
};
use std::io;

pub mod hex_view;

pub fn run(binary: BinaryFile) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, &binary);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

struct App<'a> {
    binary: &'a BinaryFile,
    tab_index: usize,
    titles: Vec<&'a str>,
    hex_viewer: hex_view::HexViewer,
}

impl<'a> App<'a> {
    fn new(binary: &'a BinaryFile) -> Self {
        Self {
            binary,
            tab_index: 0,
            titles: vec!["Info", "Sections", "Symbols", "Hex"],
            hex_viewer: hex_view::HexViewer::new(),
        }
    }

    fn next_tab(&mut self) {
        self.tab_index = (self.tab_index + 1) % self.titles.len();
    }

    fn previous_tab(&mut self) {
        if self.tab_index > 0 {
            self.tab_index -= 1;
        } else {
            self.tab_index = self.titles.len() - 1;
        }
    }
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, binary: &BinaryFile) -> Result<()> {
    let mut app = App::new(binary);

    loop {
        terminal.draw(|f| ui(f, &app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Right | KeyCode::Tab => app.next_tab(),
                KeyCode::Left | KeyCode::BackTab => app.previous_tab(),
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.titles[app.tab_index] == "Hex" {
                        app.hex_viewer.scroll_down(app.binary.data.len());
                    }
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if app.titles[app.tab_index] == "Hex" {
                        app.hex_viewer.scroll_up();
                    }
                }
                KeyCode::PageDown => {
                    if app.titles[app.tab_index] == "Hex" {
                        let height = terminal.size().map(|r| r.height).unwrap_or(20) as usize;
                        app.hex_viewer
                            .scroll_page_down(app.binary.data.len(), height);
                    }
                }
                KeyCode::PageUp => {
                    if app.titles[app.tab_index] == "Hex" {
                        let height = terminal.size().map(|r| r.height).unwrap_or(20) as usize;
                        app.hex_viewer.scroll_page_up(height);
                    }
                }
                _ => {}
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(size);

    let titles: Vec<Line> = app.titles.iter().map(|t| Line::from(*t)).collect();
    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Binary Insight: {}", app.binary.name)),
        )
        .select(app.tab_index)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(tabs, chunks[0]);

    match app.tab_index {
        0 => draw_info_tab(f, app, chunks[1]),
        1 => draw_sections_tab(f, app, chunks[1]),
        2 => draw_symbols_tab(f, app, chunks[1]),
        3 => app.hex_viewer.draw(f, chunks[1], &app.binary.data),
        _ => {}
    }
}

fn draw_info_tab(f: &mut Frame, app: &App, area: Rect) {
    let info = &app.binary.info;
    let text = vec![
        Line::from(vec![
            Span::raw("File Name: "),
            Span::styled(&app.binary.name, Style::default().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::raw("Format:    "),
            Span::styled(&info.format, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("Arch:      "),
            Span::styled(&info.arch, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("Entry Pt:  "),
            Span::styled(
                format!("0x{:x}", info.entry_point),
                Style::default().fg(Color::Magenta),
            ),
        ]),
        Line::from(""),
        Line::from(format!("Total Sections: {}", info.sections.len())),
        Line::from(format!("Total Symbols:  {}", info.symbols.len())),
    ];
    let p =
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("General Info"));
    f.render_widget(p, area);
}

fn draw_sections_tab(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Name", "Address", "Size"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.binary.info.sections.iter().map(|s| {
        Row::new(vec![
            Cell::from(s.name.clone()),
            Cell::from(format!("0x{:x}", s.addr)),
            Cell::from(format!("0x{:x}", s.size)),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Sections"));
    f.render_widget(table, area);
}

fn draw_symbols_tab(f: &mut Frame, app: &App, area: Rect) {
    let header_cells = ["Name", "Address"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = app.binary.info.symbols.iter().take(100).map(|s| {
        // Limit to 100 for now to avoid freezing TUI on large bins
        Row::new(vec![
            Cell::from(s.name.clone()),
            Cell::from(format!("0x{:x}", s.addr)),
        ])
    });

    let table = Table::new(
        rows,
        [Constraint::Percentage(70), Constraint::Percentage(30)],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Symbols (First 100)"),
    );
    f.render_widget(table, area);
}
