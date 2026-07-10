# Forensic File Analysis & Editing Tool

A comprehensive forensic file analysis and editing tool designed for legal professionals, investigators, and cybersecurity analysts. Built with Python and Tkinter.

## Features

### File Analysis
- **Hash Analysis**: Calculate MD5, SHA1, SHA256, SHA512 hashes
- **Signature Analysis**: Detect file types and suspicious patterns
- **Entropy Analysis**: Measure file randomness (identify encrypted/compressed data)
- **String Extraction**: Extract readable ASCII and Unicode strings
- **File Carving**: Recover embedded files from binary data

### File Operations
- **Multiple Views**: Hex, Text, and Raw views
- **Advanced Search**: Text, Regex, and Hex pattern search
- **Editing**: Edit files in text or hex mode with auto-backup
- **Metadata Extraction**: Extract EXIF from images and metadata from PDFs
- **Backup Management**: Create and restore backups

### Reporting
- **Export Reports**: Generate comprehensive analysis reports
- **Checksum Files**: Create and verify checksums
- **Metadata Export**: Export metadata as JSON

###  Additional Tools
- **File Comparison**: Compare two files for differences
- **Integrity Verification**: Verify file integrity using checksums
- **Forensic Analysis**: Full suite of forensic tools

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install from GitHub

```bash
# Clone the repository
git clone https://github.com/yourusername/forensic-file-tool.git
cd forensic-file-tool

# Install dependencies
pip install -r requirements.txt

# Run the application
python forensic_tool.py
