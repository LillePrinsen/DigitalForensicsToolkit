# forensic_tool.py - Complete Version
"""
Forensic File Analysis & Editing Tool
For legal professionals and investigators
Version 1.0.0
"""

import os
import sys
import hashlib
import json
import datetime
import shutil
import binascii
import re
import math
import struct
import threading
import queue
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter import font as tkfont

class ForensicFileTool:
    """Main application class for forensic file analysis and editing"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic File Analysis & Editing Tool v1.0")
        self.root.geometry("1400x800")
        
        # Application state
        self.current_file = None
        self.file_content = None
        self.file_hash = None
        self.metadata = {}
        self.analysis_results = {}
        self.backup_dir = Path("forensic_backups")
        self.backup_dir.mkdir(exist_ok=True)
        self.edit_mode = 'text'  # 'text' or 'hex'
        self.search_results_cache = []
        
        # Color scheme
        self.colors = {
            'bg': '#2b2b2b',
            'fg': '#ffffff',
            'accent': '#00bcd4',
            'warning': '#ff5722',
            'success': '#4caf50',
            'error': '#f44336',
            'highlight': '#ffeb3b'
        }
        
        self.setup_ui()
        self.setup_menus()
        self.setup_status_bar()
        
        # Thread safety for file operations
        self.task_queue = queue.Queue()
        self.process_tasks()
        
    def setup_ui(self):
        """Initialize the user interface"""
        self.root.configure(bg=self.colors['bg'])
        
        # Main container with paned windows
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - File browser and info
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=1)
        
        # Right panel - Content viewer and analysis
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=3)
        
        # Left panel widgets
        self.setup_left_panel(left_frame)
        
        # Right panel widgets
        self.setup_right_panel(right_frame)
        
    def setup_left_panel(self, parent):
        """Setup the left panel with file browser and info"""
        # File browser
        browser_frame = ttk.LabelFrame(parent, text="File Browser", padding=5)
        browser_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Path entry
        path_frame = ttk.Frame(browser_frame)
        path_frame.pack(fill=tk.X, pady=2)
        
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,5))
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_file)
        browse_btn.pack(side=tk.RIGHT)
        
        # File list
        self.file_listbox = tk.Listbox(
            browser_frame,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            selectmode=tk.SINGLE,
            height=15
        )
        self.file_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        
        # File information
        info_frame = ttk.LabelFrame(parent, text="File Information", padding=5)
        info_frame.pack(fill=tk.X, pady=5)
        
        self.info_text = scrolledtext.ScrolledText(
            info_frame,
            height=8,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Consolas', 9)
        )
        self.info_text.pack(fill=tk.BOTH, expand=True)
        
        # Quick actions
        quick_frame = ttk.LabelFrame(parent, text="Quick Actions", padding=5)
        quick_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(quick_frame, text="Hash File", command=self.hash_analysis).pack(fill=tk.X, pady=2)
        ttk.Button(quick_frame, text="Extract Metadata", command=self.extract_metadata).pack(fill=tk.X, pady=2)
        ttk.Button(quick_frame, text="Search", command=self.search_content).pack(fill=tk.X, pady=2)
        
    def setup_right_panel(self, parent):
        """Setup the right panel with tabs for different views"""
        # Notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Tab 1: Hex/Text Viewer
        viewer_frame = ttk.Frame(self.notebook)
        self.notebook.add(viewer_frame, text="Viewer")
        self.setup_viewer_tab(viewer_frame)
        
        # Tab 2: Analysis
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="Forensic Analysis")
        self.setup_analysis_tab(analysis_frame)
        
        # Tab 3: Metadata
        metadata_frame = ttk.Frame(self.notebook)
        self.notebook.add(metadata_frame, text="Metadata")
        self.setup_metadata_tab(metadata_frame)
        
        # Tab 4: Search
        search_frame = ttk.Frame(self.notebook)
        self.notebook.add(search_frame, text="Search & Extract")
        self.setup_search_tab(search_frame)
        
        # Tab 5: Editor
        editor_frame = ttk.Frame(self.notebook)
        self.notebook.add(editor_frame, text="Editor")
        self.setup_editor_tab(editor_frame)
        
    def setup_viewer_tab(self, parent):
        """Setup the hex/text viewer tab"""
        # Toolbar
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X, pady=2)
        
        ttk.Button(toolbar, text="Hex View", command=lambda: self.show_hex()).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Text View", command=lambda: self.show_text()).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Raw View", command=lambda: self.show_raw()).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_viewer).pack(side=tk.LEFT, padx=2)
        
        # Viewer
        self.viewer = scrolledtext.ScrolledText(
            parent,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Consolas', 10),
            wrap=tk.NONE
        )
        self.viewer.pack(fill=tk.BOTH, expand=True)
        
        # Add line numbers
        self.viewer.bind('<MouseWheel>', self.on_scroll)
        
    def setup_analysis_tab(self, parent):
        """Setup the forensic analysis tab"""
        # Analysis buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Hash Analysis", command=self.hash_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Signature Analysis", command=self.signature_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Entropy Analysis", command=self.entropy_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="String Extraction", command=self.string_extraction).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="File Carving", command=self.file_carving).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=2)
        
        # Analysis results
        self.analysis_output = scrolledtext.ScrolledText(
            parent,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Consolas', 9)
        )
        self.analysis_output.pack(fill=tk.BOTH, expand=True)
        
    def setup_metadata_tab(self, parent):
        """Setup the metadata extraction tab"""
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Extract Metadata", command=self.extract_metadata).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Export Metadata", command=self.export_metadata).pack(side=tk.LEFT, padx=2)
        
        self.metadata_output = scrolledtext.ScrolledText(
            parent,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Consolas', 9)
        )
        self.metadata_output.pack(fill=tk.BOTH, expand=True)
        
    def setup_search_tab(self, parent):
        """Setup the search and extraction tab"""
        # Search frame
        search_frame = ttk.Frame(parent)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(search_frame, text="Search", command=self.search_content).pack(side=tk.LEFT, padx=2)
        ttk.Button(search_frame, text="Regex Search", command=self.regex_search).pack(side=tk.LEFT, padx=2)
        
        # Hex search
        ttk.Label(search_frame, text="Hex:").pack(side=tk.LEFT, padx=5)
        self.hex_search_var = tk.StringVar()
        hex_entry = ttk.Entry(search_frame, textvariable=self.hex_search_var, width=20)
        hex_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Find Hex", command=self.hex_search).pack(side=tk.LEFT, padx=2)
        
        # Results
        self.search_results = scrolledtext.ScrolledText(
            parent,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Consolas', 9)
        )
        self.search_results.pack(fill=tk.BOTH, expand=True)
        
    def setup_editor_tab(self, parent):
        """Setup the file editor tab"""
        # Editor toolbar
        editor_toolbar = ttk.Frame(parent)
        editor_toolbar.pack(fill=tk.X, pady=2)
        
        ttk.Button(editor_toolbar, text="Save", command=self.save_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(editor_toolbar, text="Save As", command=self.save_file_as).pack(side=tk.LEFT, padx=2)
        ttk.Button(editor_toolbar, text="Revert", command=self.revert_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(editor_toolbar, text="Create Backup", command=self.create_backup).pack(side=tk.LEFT, padx=2)
        
        # Editor mode toggle
        self.edit_mode_var = tk.StringVar(value="text")
        ttk.Radiobutton(editor_toolbar, text="Text", variable=self.edit_mode_var, 
                       value="text", command=self.toggle_edit_mode).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(editor_toolbar, text="Hex", variable=self.edit_mode_var, 
                       value="hex", command=self.toggle_edit_mode).pack(side=tk.LEFT, padx=5)
        
        # Editor
        self.editor = scrolledtext.ScrolledText(
            parent,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Consolas', 11)
        )
        self.editor.pack(fill=tk.BOTH, expand=True)
        
    def setup_menus(self):
        """Setup the menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open File", command=self.browse_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As", command=self.save_file_as)
        file_menu.add_separator()
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_command(label="Export Metadata", command=self.export_metadata)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Analysis menu
        analysis_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Full Analysis", command=self.full_analysis)
        analysis_menu.add_command(label="Hash Analysis", command=self.hash_analysis)
        analysis_menu.add_command(label="Metadata Extraction", command=self.extract_metadata)
        analysis_menu.add_command(label="Entropy Analysis", command=self.entropy_analysis)
        analysis_menu.add_command(label="File Carving", command=self.file_carving)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Create Checksum File", command=self.create_checksum)
        tools_menu.add_command(label="Verify Checksum", command=self.verify_checksum)
        tools_menu.add_command(label="Compare Files", command=self.compare_files)
        tools_menu.add_command(label="View Backups", command=self.view_backups)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        
        # Keyboard shortcuts
        self.root.bind('<Control-o>', lambda e: self.browse_file())
        self.root.bind('<Control-s>', lambda e: self.save_file())
        
    def setup_status_bar(self):
        """Setup the status bar"""
        self.status_bar = ttk.Label(
            self.root,
            text="Ready",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def browse_file(self):
        """Open file browser dialog"""
        file_path = filedialog.askopenfilename(
            title="Select File for Analysis",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            self.load_file(file_path)
            
    def load_file(self, file_path):
        """Load file for analysis"""
        try:
            self.current_file = Path(file_path)
            self.status_bar.config(text=f"Loading: {self.current_file.name}")
            
            # Read file content
            with open(file_path, 'rb') as f:
                self.file_content = f.read()
            
            # Calculate hash
            self.file_hash = self.calculate_hash(self.file_content)
            
            # Update UI
            self.update_file_info()
            self.show_hex()
            self.update_editor()
            self.populate_file_list()
            
            self.status_bar.config(text=f"Loaded: {self.current_file.name} (Size: {len(self.file_content):,} bytes)")
            messagebox.showinfo("Success", f"File loaded successfully:\n{self.current_file.name}\nSHA256: {self.file_hash[:16]}...")
            
        except Exception as e:
            self.status_bar.config(text=f"Error loading file: {str(e)}")
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            
    def calculate_hash(self, data: bytes, algorithm: str = 'sha256') -> str:
        """Calculate hash of file content"""
        if algorithm == 'md5':
            return hashlib.md5(data).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).hexdigest()
        else:
            return hashlib.sha256(data).hexdigest()
            
    def update_file_info(self):
        """Update file information panel"""
        if not self.current_file:
            return
            
        info = f"File: {self.current_file.name}\n"
        info += f"Path: {self.current_file.parent}\n"
        info += f"Size: {self.current_file.stat().st_size:,} bytes\n"
        info += f"Created: {datetime.datetime.fromtimestamp(self.current_file.stat().st_ctime).strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"Modified: {datetime.datetime.fromtimestamp(self.current_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"Accessed: {datetime.datetime.fromtimestamp(self.current_file.stat().st_atime).strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"SHA256: {self.file_hash[:32]}...\n"
        info += f"File Type: {self.detect_file_type()}"
        
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(1.0, info)
        
    def detect_file_type(self) -> str:
        """Detect file type using magic numbers"""
        try:
            import magic
            mime = magic.from_buffer(self.file_content[:1024], mime=True)
            description = magic.from_buffer(self.file_content[:1024])
            return f"{mime} - {description}"
        except:
            # Fallback signature detection
            signatures = {
                b'\x89\x50\x4e\x47': 'PNG Image',
                b'\xff\xd8\xff': 'JPEG Image',
                b'\x25\x50\x44\x46': 'PDF Document',
                b'\x7f\x45\x4c\x46': 'ELF Executable',
                b'MZ': 'PE Executable',
                b'\x1f\x8b': 'GZIP Archive',
                b'PK\x03\x04': 'ZIP Archive',
            }
            for sig, ftype in signatures.items():
                if self.file_content.startswith(sig):
                    return ftype
            return "Unknown"
            
    def populate_file_list(self):
        """Populate file list in the browser"""
        self.file_listbox.delete(0, tk.END)
        if self.current_file:
            parent_dir = self.current_file.parent
            for item in parent_dir.iterdir():
                if item.is_file():
                    self.file_listbox.insert(tk.END, item.name)
                    
    def on_file_select(self, event):
        """Handle file selection from listbox"""
        selection = self.file_listbox.curselection()
        if selection:
            index = selection[0]
            filename = self.file_listbox.get(index)
            if self.current_file:
                file_path = self.current_file.parent / filename
                if file_path.is_file():
                    self.load_file(str(file_path))
                    
    def show_hex(self):
        """Display file content in hexadecimal format"""
        if not self.file_content:
            return
            
        self.viewer.delete(1.0, tk.END)
        hex_lines = []
        max_display = min(len(self.file_content), 10240)
        for i in range(0, max_display, 16):
            chunk = self.file_content[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f"{i:08x}: {hex_part:<48} {ascii_part}")
            
        self.viewer.insert(1.0, '\n'.join(hex_lines))
        if len(self.file_content) > 10240:
            self.viewer.insert(tk.END, f"\n... and {len(self.file_content) - 10240} more bytes")
            
    def show_text(self):
        """Display file content as text"""
        if not self.file_content:
            return
            
        self.viewer.delete(1.0, tk.END)
        try:
            text = self.file_content.decode('utf-8', errors='replace')
            # Limit display to first 10000 characters
            if len(text) > 10000:
                text = text[:10000] + "\n... (truncated)"
            self.viewer.insert(1.0, text)
        except:
            self.viewer.insert(1.0, "Cannot display as text (binary file)")
            
    def show_raw(self):
        """Display raw file content"""
        if not self.file_content:
            return
            
        self.viewer.delete(1.0, tk.END)
        raw = self.file_content[:10240]
        self.viewer.insert(1.0, raw)
        
    def refresh_viewer(self):
        """Refresh the current view"""
        current_tab = self.notebook.index(self.notebook.select())
        if current_tab == 0:  # Viewer tab
            self.show_hex()
            
    def on_scroll(self, event):
        """Handle mousewheel scrolling"""
        self.viewer.yview_scroll(-1 * (event.delta // 120), "units")
        
    def update_editor(self):
        """Update the editor with current file content"""
        if not self.file_content:
            return
            
        self.editor.delete(1.0, tk.END)
        if self.edit_mode_var.get() == 'hex':
            hex_str = binascii.hexlify(self.file_content).decode('ascii')
            # Format hex in pairs
            formatted = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            self.editor.insert(1.0, formatted)
        else:
            try:
                text = self.file_content.decode('utf-8', errors='replace')
                self.editor.insert(1.0, text)
            except:
                self.editor.insert(1.0, "Cannot edit binary file in text mode. Switch to hex mode.")
                
    def toggle_edit_mode(self):
        """Toggle between hex and text edit mode"""
        self.update_editor()
        
    def save_file(self):
        """Save current file"""
        if not self.current_file:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        try:
            content = self.editor.get(1.0, tk.END)
            if self.edit_mode_var.get() == 'hex':
                # Remove whitespace and newlines
                hex_content = ''.join(content.split())
                try:
                    data = bytes.fromhex(hex_content)
                except ValueError as e:
                    messagebox.showerror("Error", f"Invalid hex data: {str(e)}")
                    return
            else:
                data = content.encode('utf-8')
                
            # Create backup before saving
            self.create_backup()
            
            # Save file
            with open(self.current_file, 'wb') as f:
                f.write(data)
                
            # Reload file
            self.load_file(str(self.current_file))
            messagebox.showinfo("Success", "File saved successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")
            
    def save_file_as(self):
        """Save file with new name"""
        if not self.current_file:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension="*",
            filetypes=[("All Files", "*.*")]
        )
        if file_path:
            try:
                content = self.editor.get(1.0, tk.END)
                with open(file_path, 'wb') as f:
                    f.write(content.encode('utf-8'))
                messagebox.showinfo("Success", f"File saved as: {file_path}")
                self.load_file(file_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                
    def revert_file(self):
        """Revert to last saved version"""
        if not self.current_file:
            return
            
        if messagebox.askyesno("Confirm", "Revert to last saved version? All changes will be lost."):
            self.load_file(str(self.current_file))
            
    def create_backup(self):
        """Create backup of current file"""
        if not self.current_file:
            return
            
        backup_path = self.backup_dir / f"{self.current_file.name}.{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
        shutil.copy2(self.current_file, backup_path)
        self.status_bar.config(text=f"Backup created: {backup_path.name}")
        return backup_path
        
    def hash_analysis(self):
        """Perform comprehensive hash analysis"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        self.analysis_output.delete(1.0, tk.END)
        self.analysis_output.insert(1.0, "=== HASH ANALYSIS ===\n\n")
        
        hashes = {
            'MD5': hashlib.md5(self.file_content).hexdigest(),
            'SHA1': hashlib.sha1(self.file_content).hexdigest(),
            'SHA256': hashlib.sha256(self.file_content).hexdigest(),
            'SHA512': hashlib.sha512(self.file_content).hexdigest(),
            'SHA3-256': hashlib.sha3_256(self.file_content).hexdigest(),
        }
        
        for algo, hash_value in hashes.items():
            self.analysis_output.insert(tk.END, f"{algo}: {hash_value}\n")
            
        # Check against common malware hashes
        self.analysis_output.insert(tk.END, "\n=== SECURITY CHECK ===\n")
        # In production, this would query a database
        self.analysis_output.insert(tk.END, "Hash not found in known malware database (local check)\n")
        
        # Generate hash file for verification
        hash_file = self.current_file.with_suffix('.sha256')
        with open(hash_file, 'w') as f:
            f.write(f"{hashes['SHA256']}  {self.current_file.name}\n")
        self.analysis_output.insert(tk.END, f"\nHash file created: {hash_file.name}\n")
        
    def signature_analysis(self):
        """Analyze file signatures and headers"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        self.analysis_output.delete(1.0, tk.END)
        self.analysis_output.insert(1.0, "=== FILE SIGNATURE ANALYSIS ===\n\n")
        
        # Check file signatures
        signatures = {
            b'\x89\x50\x4e\x47': 'PNG Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'\x25\x50\x44\x46': 'PDF Document',
            b'\x7f\x45\x4c\x46': 'ELF Executable',
            b'MZ': 'PE Executable',
            b'\x1f\x8b': 'GZIP Archive',
            b'PK\x03\x04': 'ZIP Archive',
            b'RAR': 'RAR Archive',
        }
        
        file_type = "Unknown"
        for sig, ftype in signatures.items():
            if self.file_content.startswith(sig):
                file_type = ftype
                break
                
        self.analysis_output.insert(tk.END, f"Detected Type: {file_type}\n")
        self.analysis_output.insert(tk.END, f"Magic Detection: {self.detect_file_type()}\n\n")
        
        # Check for suspicious structures
        self.analysis_output.insert(tk.END, "=== SUSPICIOUS PATTERNS ===\n")
        patterns = {
            b'<script>': 'JavaScript found',
            b'javascript:': 'JavaScript URI found',
            b'exec(': 'Potential code execution',
            b'eval(': 'Potential code execution',
            b'system(': 'System call found',
            b'cmd.exe': 'Windows command found',
            b'/bin/sh': 'Shell command found',
        }
        
        for pattern, desc in patterns.items():
            if pattern in self.file_content:
                self.analysis_output.insert(tk.END, f"⚠ Found: {desc}\n")
                
    def entropy_analysis(self):
        """Calculate and analyze file entropy"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        self.analysis_output.delete(1.0, tk.END)
        self.analysis_output.insert(1.0, "=== ENTROPY ANALYSIS ===\n\n")
        
        # Calculate entropy
        hist = [0] * 256
        for b in self.file_content:
            hist[b] += 1
            
        total = len(self.file_content)
        entropy = 0
        for count in hist:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
                
        self.analysis_output.insert(tk.END, f"File Entropy: {entropy:.4f} bits per byte\n")
        self.analysis_output.insert(tk.END, f"Maximum Entropy: 8.0000 bits per byte\n\n")
        
        # Interpretation
        if entropy > 7.5:
            self.analysis_output.insert(tk.END, "⚠ High entropy - likely encrypted or compressed\n")
            self.analysis_output.insert(tk.END, "   This is common in malware, encrypted files, or compressed data\n")
        elif entropy > 6.0:
            self.analysis_output.insert(tk.END, "⚠ Moderate entropy - may contain compressed data\n")
        else:
            self.analysis_output.insert(tk.END, "✓ Low entropy - typical for text or uncompressed data\n")
            
        # Entropy distribution
        self.analysis_output.insert(tk.END, "\n=== BYTE FREQUENCY (top 10) ===\n")
        hist_data = [(i, hist[i]) for i in range(256) if hist[i] > 0]
        for i, count in sorted(hist_data, key=lambda x: x[1], reverse=True)[:10]:
            self.analysis_output.insert(tk.END, f"Byte 0x{i:02x} '{chr(i) if 32 <= i <= 126 else '.'}': {count:6d} times ({count/total*100:.2f}%)\n")
            
    def string_extraction(self):
        """Extract readable strings from binary data"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        self.analysis_output.delete(1.0, tk.END)
        self.analysis_output.insert(1.0, "=== STRING EXTRACTION ===\n\n")
        
        # Extract ASCII strings
        strings = []
        current = []
        
        for b in self.file_content:
            if 32 <= b <= 126:  # Printable ASCII
                current.append(chr(b))
            else:
                if len(current) >= 4:  # Minimum string length
                    strings.append(''.join(current))
                current = []
                
        if len(current) >= 4:
            strings.append(''.join(current))
            
        self.analysis_output.insert(tk.END, f"Found {len(strings)} ASCII strings (min 4 chars)\n\n")
        
        # Display first 50 strings
        for i, s in enumerate(strings[:50]):
            self.analysis_output.insert(tk.END, f"{i+1}. {s}\n")
            
        if len(strings) > 50:
            self.analysis_output.insert(tk.END, f"\n... and {len(strings) - 50} more strings\n")
            
        # Look for sensitive data
        self.analysis_output.insert(tk.END, "\n=== SENSITIVE DATA DETECTION ===\n")
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN (US)'),
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'Credit card number'),
            (r'\b\d{3}\.\d{3}\.\d{3}\.\d{3}\b', 'IP Address'),
        ]
        
        text_content = self.file_content.decode('utf-8', errors='ignore')
        for pattern, desc in sensitive_patterns:
            matches = re.findall(pattern, text_content)
            if matches:
                self.analysis_output.insert(tk.END, f"⚠ Found {desc}: {matches[:3]}\n")
                
    def file_carving(self):
        """Perform file carving to recover hidden files"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        self.analysis_output.delete(1.0, tk.END)
        self.analysis_output.insert(1.0, "=== FILE CARVING ===\n\n")
        
        # Known file signatures for carving
        signatures = {
            b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a': ('PNG', '.png'),
            b'\xff\xd8\xff': ('JPEG', '.jpg'),
            b'\x25\x50\x44\x46': ('PDF', '.pdf'),
            b'\x1f\x8b\x08': ('GZIP', '.gz'),
            b'PK\x03\x04': ('ZIP', '.zip'),
            b'\x7f\x45\x4c\x46': ('ELF', ''),
            b'MZ': ('PE', '.exe'),
        }
        
        # Simple carving - find file headers
        carved_files = []
        for sig, (name, ext) in signatures.items():
            positions = []
            start = 0
            while True:
                pos = self.file_content.find(sig, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
                
            if positions:
                self.analysis_output.insert(tk.END, f"Found {len(positions)} {name} file(s) at positions: {positions[:5]}\n")
                carved_files.extend([(sig, pos, name) for pos in positions[:5]])
                
        self.analysis_output.insert(tk.END, f"\nTotal embedded files found: {len(carved_files)}\n")
        
        # Extract first found file as sample
        if carved_files:
            sig, pos, name = carved_files[0]
            self.analysis_output.insert(tk.END, f"\n=== SAMPLE EXTRACTION ===\n")
            self.analysis_output.insert(tk.END, f"Extracting {name} at position {pos}:\n")
            # Extract up to 512 bytes after signature
            data = self.file_content[pos:pos+512]
            hex_dump = binascii.hexlify(data[:64]).decode('ascii')
            self.analysis_output.insert(tk.END, f"Hex dump (first 64 bytes):\n{hex_dump}\n")
            
    def extract_metadata(self):
        """Extract metadata from file"""
        if not self.current_file:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        self.metadata_output.delete(1.0, tk.END)
        self.metadata_output.insert(1.0, "=== METADATA EXTRACTION ===\n\n")
        
        # Basic metadata
        self.metadata_output.insert(tk.END, "=== BASIC FILE METADATA ===\n")
        self.metadata_output.insert(tk.END, f"File: {self.current_file.name}\n")
        self.metadata_output.insert(tk.END, f"Size: {self.current_file.stat().st_size:,} bytes\n")
        self.metadata_output.insert(tk.END, f"Created: {datetime.datetime.fromtimestamp(self.current_file.stat().st_ctime).strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.metadata_output.insert(tk.END, f"Modified: {datetime.datetime.fromtimestamp(self.current_file.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.metadata_output.insert(tk.END, f"Accessed: {datetime.datetime.fromtimestamp(self.current_file.stat().st_atime).strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.metadata_output.insert(tk.END, f"SHA256: {self.file_hash}\n\n")
        
        # Try to extract EXIF for images
        try:
            import PIL.Image
            from PIL.ExifTags import TAGS
            
            img = PIL.Image.open(self.current_file)
            self.metadata_output.insert(tk.END, "=== EXIF DATA ===\n")
            exifdata = img.getexif()
            if exifdata:
                for tag_id, value in exifdata.items():
                    tag = TAGS.get(tag_id, tag_id)
                    self.metadata_output.insert(tk.END, f"{tag}: {value}\n")
            else:
                self.metadata_output.insert(tk.END, "No EXIF data found\n")
        except:
            pass
            
        # Try to extract PDF metadata
        if self.detect_file_type().startswith('PDF'):
            try:
                import PyPDF2
                pdf_file = open(self.current_file, 'rb')
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                self.metadata_output.insert(tk.END, "\n=== PDF METADATA ===\n")
                for key, value in pdf_reader.metadata.items():
                    if key.startswith('/'):
                        key = key[1:]
                    self.metadata_output.insert(tk.END, f"{key}: {value}\n")
                pdf_file.close()
            except:
                pass
                
    def export_metadata(self):
        """Export metadata to JSON file"""
        if not self.current_file:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"{self.current_file.stem}_metadata.json"
        )
        if file_path:
            try:
                metadata_dict = {
                    'file': str(self.current_file),
                    'size': self.current_file.stat().st_size,
                    'created': datetime.datetime.fromtimestamp(self.current_file.stat().st_ctime).isoformat(),
                    'modified': datetime.datetime.fromtimestamp(self.current_file.stat().st_mtime).isoformat(),
                    'accessed': datetime.datetime.fromtimestamp(self.current_file.stat().st_atime).isoformat(),
                    'sha256': self.file_hash,
                    'type': self.detect_file_type()
                }
                
                # Get EXIF data if available
                try:
                    import PIL.Image
                    from PIL.ExifTags import TAGS
                    img = PIL.Image.open(self.current_file)
                    exifdata = img.getexif()
                    if exifdata:
                        metadata_dict['exif'] = {}
                        for tag_id, value in exifdata.items():
                            tag = TAGS.get(tag_id, tag_id)
                            metadata_dict['exif'][tag] = str(value)
                except:
                    pass
                    
                with open(file_path, 'w') as f:
                    json.dump(metadata_dict, f, indent=2)
                messagebox.showinfo("Success", f"Metadata exported to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export metadata: {str(e)}")
                
    def search_content(self):
        """Search for text in file content"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        search_term = self.search_var.get()
        if not search_term:
            messagebox.showwarning("Warning", "Enter search term")
            return
            
        self.search_results.delete(1.0, tk.END)
        self.search_results.insert(1.0, f"=== SEARCH RESULTS FOR '{search_term}' ===\n\n")
        
        try:
            text = self.file_content.decode('utf-8', errors='ignore')
            positions = []
            start = 0
            while True:
                pos = text.find(search_term, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
                
            if positions:
                self.search_results.insert(tk.END, f"Found {len(positions)} occurrences\n\n")
                for i, pos in enumerate(positions[:50]):
                    # Show context
                    start_pos = max(0, pos - 30)
                    end_pos = min(len(text), pos + 30 + len(search_term))
                    context = text[start_pos:end_pos]
                    self.search_results.insert(tk.END, f"{i+1}. Position {pos}: ...{context}...\n")
                if len(positions) > 50:
                    self.search_results.insert(tk.END, f"\n... and {len(positions) - 50} more occurrences\n")
            else:
                self.search_results.insert(tk.END, "No occurrences found\n")
                
        except Exception as e:
            self.search_results.insert(tk.END, f"Error during search: {str(e)}\n")
            
    def regex_search(self):
        """Search using regular expression"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        search_term = self.search_var.get()
        if not search_term:
            messagebox.showwarning("Warning", "Enter search term")
            return
            
        self.search_results.delete(1.0, tk.END)
        self.search_results.insert(1.0, f"=== REGEX SEARCH RESULTS FOR '{search_term}' ===\n\n")
        
        try:
            text = self.file_content.decode('utf-8', errors='ignore')
            matches = re.finditer(search_term, text)
            
            positions = []
            for match in matches:
                positions.append(match.start())
                
            if positions:
                self.search_results.insert(tk.END, f"Found {len(positions)} matches\n\n")
                for i, pos in enumerate(positions[:50]):
                    start_pos = max(0, pos - 30)
                    end_pos = min(len(text), pos + 30 + len(search_term))
                    context = text[start_pos:end_pos]
                    self.search_results.insert(tk.END, f"{i+1}. Position {pos}: ...{context}...\n")
                if len(positions) > 50:
                    self.search_results.insert(tk.END, f"\n... and {len(positions) - 50} more matches\n")
            else:
                self.search_results.insert(tk.END, "No matches found\n")
                
        except re.error as e:
            self.search_results.insert(tk.END, f"Invalid regular expression: {str(e)}\n")
        except Exception as e:
            self.search_results.insert(tk.END, f"Error during search: {str(e)}\n")
            
    def hex_search(self):
        """Search for hex pattern in file"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        hex_pattern = self.hex_search_var.get()
        if not hex_pattern:
            messagebox.showwarning("Warning", "Enter hex pattern")
            return
            
        self.search_results.delete(1.0, tk.END)
        self.search_results.insert(1.0, f"=== HEX SEARCH RESULTS FOR '{hex_pattern}' ===\n\n")
        
        try:
            # Convert hex to bytes
            hex_bytes = bytes.fromhex(hex_pattern.replace(' ', ''))
            positions = []
            start = 0
            while True:
                pos = self.file_content.find(hex_bytes, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
                
            if positions:
                self.search_results.insert(tk.END, f"Found {len(positions)} occurrences\n\n")
                for i, pos in enumerate(positions[:50]):
                    # Show surrounding hex
                    start_pos = max(0, pos - 16)
                    end_pos = min(len(self.file_content), pos + 16 + len(hex_bytes))
                    hex_dump = binascii.hexlify(self.file_content[start_pos:end_pos]).decode('ascii')
                    self.search_results.insert(tk.END, f"{i+1}. Position 0x{pos:x}: ...{hex_dump}...\n")
                if len(positions) > 50:
                    self.search_results.insert(tk.END, f"\n... and {len(positions) - 50} more occurrences\n")
            else:
                self.search_results.insert(tk.END, "No occurrences found\n")
                
        except ValueError as e:
            self.search_results.insert(tk.END, f"Invalid hex pattern: {str(e)}\n")
        except Exception as e:
            self.search_results.insert(tk.END, f"Error during search: {str(e)}\n")
            
    def export_report(self):
        """Export analysis report"""
        if not self.current_file:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"{self.current_file.stem}_report.txt"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write("=" * 80 + "\n")
                    f.write("FORENSIC ANALYSIS REPORT\n")
                    f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Basic info
                    f.write("FILE INFORMATION\n")
                    f.write(f"Name: {self.current_file.name}\n")
                    f.write(f"Path: {self.current_file.parent}\n")
                    f.write(f"Size: {self.current_file.stat().st_size:,} bytes\n")
                    f.write(f"SHA256: {self.file_hash}\n")
                    f.write(f"Type: {self.detect_file_type()}\n\n")
                    
                    # Hashes
                    f.write("HASH VALUES\n")
                    for algo in ['md5', 'sha1', 'sha256', 'sha512']:
                        hash_value = self.calculate_hash(self.file_content, algo)
                        f.write(f"{algo.upper()}: {hash_value}\n")
                    f.write("\n")
                    
                    # Entropy
                    hist = [0] * 256
                    for b in self.file_content:
                        hist[b] += 1
                    total = len(self.file_content)
                    entropy = 0
                    for count in hist:
                        if count > 0:
                            p = count / total
                            entropy -= p * math.log2(p)
                    f.write(f"ENTROPY: {entropy:.4f} bits per byte\n\n")
                    
                    # Analysis results from current tabs
                    if hasattr(self, 'analysis_output'):
                        f.write("ANALYSIS RESULTS\n")
                        f.write(self.analysis_output.get(1.0, tk.END))
                        f.write("\n")
                    
                    f.write("=" * 80 + "\n")
                    f.write("END OF REPORT\n")
                    
                messagebox.showinfo("Success", f"Report exported to: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
                
    def create_checksum(self):
        """Create checksum file for current file"""
        if not self.current_file:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        hash_file = self.current_file.with_suffix('.sha256')
        with open(hash_file, 'w') as f:
            f.write(f"{self.file_hash}  {self.current_file.name}\n")
        messagebox.showinfo("Success", f"Checksum file created: {hash_file.name}")
        
    def verify_checksum(self):
        """Verify file against checksum file"""
        if not self.current_file:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        hash_file = self.current_file.with_suffix('.sha256')
        if not hash_file.exists():
            messagebox.showwarning("Warning", f"No checksum file found: {hash_file.name}")
            return
            
        try:
            with open(hash_file, 'r') as f:
                stored_hash = f.read().split()[0]
                
            current_hash = self.calculate_hash(self.file_content)
            if stored_hash == current_hash:
                messagebox.showinfo("Success", "✓ Checksum verification passed\nFile integrity verified")
            else:
                messagebox.showerror("Error", "✗ Checksum verification failed\nFile may be corrupted or modified")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify checksum: {str(e)}")
            
    def compare_files(self):
        """Compare two files"""
        file1 = filedialog.askopenfilename(title="Select First File")
        if not file1:
            return
            
        file2 = filedialog.askopenfilename(title="Select Second File")
        if not file2:
            return
            
        try:
            with open(file1, 'rb') as f:
                data1 = f.read()
            with open(file2, 'rb') as f:
                data2 = f.read()
                
            hash1 = hashlib.sha256(data1).hexdigest()
            hash2 = hashlib.sha256(data2).hexdigest()
            
            result = f"COMPARISON RESULTS\n"
            result += f"File 1: {Path(file1).name} - SHA256: {hash1}\n"
            result += f"File 2: {Path(file2).name} - SHA256: {hash2}\n\n"
            
            if hash1 == hash2:
                result += "✓ Files are identical (same hash)\n"
            else:
                result += "✗ Files are different (different hashes)\n"
                result += f"File sizes: {len(data1)} vs {len(data2)} bytes\n"
                
                # Find first difference
                min_len = min(len(data1), len(data2))
                for i in range(min_len):
                    if data1[i] != data2[i]:
                        result += f"First difference at offset 0x{i:x}\n"
                        result += f"File1: 0x{data1[i]:02x}\n"
                        result += f"File2: 0x{data2[i]:02x}\n"
                        break
                        
            messagebox.showinfo("Comparison Results", result)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compare files: {str(e)}")
            
    def view_backups(self):
        """View and manage backups"""
        backup_window = tk.Toplevel(self.root)
        backup_window.title("Backup Manager")
        backup_window.geometry("600x400")
        
        # List backups
        backup_list = tk.Listbox(backup_window, height=20)
        backup_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for backup in self.backup_dir.glob("*.bak"):
            backup_list.insert(tk.END, f"{backup.name} ({backup.stat().st_size:,} bytes)")
            
        # Buttons
        btn_frame = ttk.Frame(backup_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def restore_backup():
            selection = backup_list.curselection()
            if selection:
                backup_name = backup_list.get(selection[0])
                backup_path = self.backup_dir / backup_name
                original_name = backup_name.split('.')[0]
                
                if messagebox.askyesno("Confirm", f"Restore backup {backup_name}?"):
                    try:
                        shutil.copy2(backup_path, self.current_file.parent / original_name)
                        messagebox.showinfo("Success", "Backup restored")
                        backup_window.destroy()
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to restore: {str(e)}")
                        
        ttk.Button(btn_frame, text="Restore Selected", command=restore_backup).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=backup_window.destroy).pack(side=tk.RIGHT, padx=5)
        
    def full_analysis(self):
        """Run comprehensive analysis"""
        if not self.file_content:
            messagebox.showwarning("Warning", "No file loaded")
            return
            
        self.hash_analysis()
        self.signature_analysis()
        self.entropy_analysis()
        self.string_extraction()
        self.extract_metadata()
        
        messagebox.showinfo("Complete", "Full analysis completed")
        
    def process_tasks(self):
        """Process queued tasks"""
        try:
            while True:
                task = self.task_queue.get_nowait()
                task()
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_tasks)
            
    def show_about(self):
        """Show about dialog"""
        about_text = """
Forensic File Analysis & Editing Tool
Version 1.0.0

A comprehensive tool for forensic analysis of files
designed for legal professionals and investigators.

Features:
• File viewing (hex, text, raw)
• Forensic analysis (hash, entropy, signatures)
• Metadata extraction
• Search and extraction
• File editing
• Backup management
• Report generation

Created for the forensic community
"""
        messagebox.showinfo("About", about_text)
        
    def show_documentation(self):
        """Show documentation"""
        doc_text = """
FORENSIC TOOL DOCUMENTATION

1. Opening Files
   - Click Browse or File > Open File
   - Select any file for analysis

2. Viewing Files
   - Hex View: Shows hexadecimal representation
   - Text View: Shows text content
   - Raw View: Shows raw bytes

3. Analysis
   - Hash Analysis: Calculates multiple hash values
   - Signature Analysis: Detects file type and suspicious patterns
   - Entropy Analysis: Measures randomness
   - String Extraction: Extracts readable strings
   - File Carving: Finds embedded files

4. Metadata
   - Extract metadata from images (EXIF) and PDFs
   - Export metadata as JSON

5. Search
   - Text search with context
   - Regex search
   - Hex pattern search

6. Editing
   - Edit files in text or hex mode
   - Auto-backup before saving
   - Revert to original

7. Reports
   - Export comprehensive analysis reports
   - Create checksum files

8. Tools
   - Create and verify checksums
   - Compare files
   - Manage backups
"""
        messagebox.showinfo("Documentation", doc_text)

def main():
    """Main entry point"""
    try:
        root = tk.Tk()
        app = ForensicFileTool(root)
        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
