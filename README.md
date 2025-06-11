# Libero Email Validator

Libero Email Validator ("the Tool") checks login details for Libero email accounts. It tries POP3 and IMAP servers in quick succession and notes which addresses work. It can use many network connections at once so big lists finish faster.

## 1. What the Tool Does
- Verifies email and password combinations for Libero mailboxes.
- Supports both POP3 and IMAP protocols.
- Runs many checks at the same time to save you hours of waiting.

## 2. System Requirements
- **Operating systems**: Windows 10+, macOS 11+, or any modern Linux.
- **Hardware**: At least 4 GB of RAM and around 50 MB of free disk space.
- **Software**: Rust 1.77 or newer if building from source. Pre-built downloads need no extra software.

## 3. Download & Installation
1. Visit the project page at `https://example.com/libero-validator`.
   - [Screenshot: Download page]
2. Download the installer for your system:
   - **Windows**: `libero-validator-setup.exe`
   - **macOS**: `libero-validator.dmg`
   - **Linux**: `libero-validator.tar.gz`
3. Run the installer and follow the prompts:
   - On Windows, double-click the `.exe` file and choose `Install`.
     - [Screenshot: Windows installer]
   - On macOS, open the `.dmg`, drag the app into `Applications`.
     - [Screenshot: macOS drag-and-drop]
   - On Linux, extract the archive and run `install.sh`.
     - [Screenshot: Terminal showing install.sh]

### Building from Source
If you prefer to build the Tool yourself:
1. Install Rust from <https://www.rust-lang.org/tools/install>.
2. Clone the repository: `git clone https://example.com/libero-validator.git`.
3. Run `cargo build --release` in the project folder.
   - [Screenshot: Build process]

## 4. First-Time Setup
1. Launch the Tool from the start menu or by double-clicking its icon.
2. On the first run you will be asked for a license key.
   - Copy and paste the key you received after purchase.
   - [Screenshot: License entry]
3. If you plan to use proxies, edit the `proxies.txt` file located next to the app.
   - One proxy per line, e.g. `127.0.0.1:8080`.

## 5. Basic Usage Workflow
1. Open the Tool.
2. Click **Load Combos** and select a text file of `email:password` entries.
   - [Screenshot: Loading combos]
3. Choose whether to check POP3 only or all protocols.
4. Press **Start** to begin scanning.
   - Progress appears in the built‑in dashboard.
   - [Screenshot: Running check]
5. When finished, results are saved as `valid.txt`, `invalid.txt`, and `error.txt` in the same folder.

## 6. Troubleshooting & Tips
- **"No connection" or timeouts**: Check your internet connection and proxy settings.
- **License errors**: Re-enter your key carefully. Keys are case-sensitive.
- **Logs**: Find the `logs` folder next to the program file. Attach these logs if contacting support.
- **Help**: Visit the support forum at `https://example.com/support` or email `support@example.com`.

