<div align="center">

![BinaryInsight Logo](assets/logo.svg)

# BinaryInsight

**Advanced Binary Analysis & inspection Tool**

[![CI](https://github.com/ismailtsdln/BinaryInsight/actions/workflows/ci.yml/badge.svg)](https://github.com/ismailtsdln/BinaryInsight/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

BinaryInsight is a modern, high-performance binary analysis tool designed for reverse engineers and security researchers. Written in Rust, it provides both a rich **Terminal User Interface (TUI)** for interactive exploration and a **Command Line Interface (CLI)** for automated reporting.

It supports parsing and analyzing **ELF**, **PE**, and **Mach-O** binary formats, offering deep insights into sections, symbols, strings, and security mitigations.

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Contributing](#contributing)

</div>

---

## 🚀 Features

- **📂 Multi-Format Support**
  - **ELF** (Linux executables & shared libraries)
  - **PE** (Windows executables & DLLs)
  - **Mach-O** (macOS executables & dylibs)

- **🖥️ Interactive TUI Mode**
  - Navigate through binary details using a keyboard-driven interface.
  - Tabs for General Info, Sections, Symbols, and more.
  - Responsive layout built with `ratatui`.

- **📝 CLI Report Mode**
  - Generate detailed text reports for scripting and automation.
  - Pipe output to files or other tools.

- **🛡️ Security Analysis**
  - **ELF**: Detect PIE, NX (GNU Stack), RELRO (Partial/Full), Stack Canaries.
  - **PE**: Detect ASLR, DEP (NX), DLL Characteristics.
  - **Mach-O**: Detect PIE, NX (MH_NO_HEAP_EXECUTION/Stack checks).

- **search String Extraction**
  - Fast extraction of printable ASCII strings.
  - Filter noise to find relevant data.

## 📦 Installation

### From Source
Ensure you have Rust and Cargo installed.

```bash
git clone https://github.com/ismailtsdln/BinaryInsight.git
cd BinaryInsight
cargo install --path binary-insight-cli
```

## 🛠️ Usage

BinaryInsight acts as a single binary `binary-insight-cli`.

### Interactive Mode (TUI)
Simply run the tool with the target binary path. This opens the interactive visualizer.

```bash
binary-insight-cli /path/to/target/binary
```

**Controls:**
- `Right` / `Tab`: Next Tab
- `Left` / `Shift+Tab`: Previous Tab
- `q`: Quit

### Headless Mode (CLI)
For quick analysis or piping output, use the `--cli` flag.

```bash
binary-insight-cli --cli /bin/ls
```

**Example Output:**
```text
=== Binary Analysis Report ===
File:         ls
Format:       Mach-O
Arch:         Unknown
Entry Point:  0x100001234

[Security Features]
  PIE:    true
  NX:     true
  RELRO:  false
  Canary: false

[Sections]
Name                 Address            Size              
__text               0x100000000        0x1234          
...
```

## 🏗️ Architecture

The project is organized as a Cargo workspace:

- **`binary-insight-core`**: The library crate containing parsing logic, analysis modules, and data structures. It uses `goblin` for binary parsing.
- **`binary-insight-cli`**: The application crate that consumes specific core features to render the TUI (via `ratatui`) or print CLI reports.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
