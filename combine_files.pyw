# -*- coding: utf-8 -*-
"""
Source Code Combiner - v2.1

A tool to recursively find and combine text-based source code files from a directory
into a single output file. Features a polished graphical user interface and a powerful
command-line mode.

Key Improvements in this Version:
- FIXED: Corrected an AttributeError crash caused by a variable name typo in the UI code.
- FIXED: UI controls no longer disappear on window resize, thanks to a robust grid layout.
- NEW: Runs without a console window by using the .pyw extension.
- OPTIMIZED: Directory tree is now scanned only ONCE, significantly improving performance.
- ROBUST: Thread-safe GUI updates via a queue, preventing race conditions.
- ENHANCED: Cleaner, more intuitive, and user-friendly UI with better organization.
- REFINED: Codebase adheres to modern Python best practices (dataclasses, pathlib, etc.).
- POWERFUL: Expanded command-line arguments for headless operation.
"""

import os
import sys
import time
import argparse
import fnmatch
import threading
import queue
from pathlib import Path
from typing import List, Set, Optional, Callable, Tuple
from dataclasses import dataclass, field

# --- GUI Imports ---
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# --- Configuration Dataclass ---
@dataclass
class Config:
    """Holds all configuration parameters for the application."""
    root_dir: Path = field(default_factory=Path.home)
    output_dir: Path = field(default_factory=lambda: Path.home() / "Downloads")
    output_filename: str = "combined_project_files.txt"
    limit_file_size: bool = True
    max_file_size_mb: float = 10.0
    skip_dirs: Set[str] = field(default_factory=lambda: {
        ".git", ".vscode", "node_modules", "bin", "obj", "build", "dist",
        "__pycache__", ".svn", ".hg", "venv", "ida-sdk", "firebase", "driver", "build", "tools", "mapper", "libs", "bot"
    })
    exclude_patterns: Set[str] = field(default_factory=lambda: {
        "*.log", "*.tmp", "*.bak", "*.pyc", "*.swp", "*.DS_Store", "whoswho_encrypted.h", "WhosWho.c", "WindMapper.c"
    })
    include_extensions: Set[str] = field(default_factory=lambda: {
        '.sln', '.vcxproj', '.filters', '.user', '.h', '.hpp', '.hxx', '.c', '.cpp',
        '.cxx', '.cs', '.inl', '.txt', '.md', '.readme', '.html', '.css', '.js',
        '.ts', '.py', '.sh', '.bat', '.ps1', '.jsx', '.tsx', '.vue', '.scss',
        '.sass', '.less', '.json', '.xml', '.yaml', '.yml', '.ini', '.cfg', '.f',
        '.for', '.f90', '.java', '.kt', '.rs', '.go', '.rb', '.php', '.sql',
        '.glsl', '.hlsl', '.shader', '.swift', '.m', '.mm', '.dockerfile', '.*ignore'
    })

    @property
    def max_file_size_bytes(self) -> Optional[int]:
        """Returns max file size in bytes if limit is enabled."""
        if self.limit_file_size:
            return int(self.max_file_size_mb * 1024 * 1024)
        return None

# --- Core Logic ---

def read_file_with_fallback(file_path: Path) -> Tuple[Optional[str], Optional[str]]:
    """
    Tries to read a file with a list of common encodings.
    Returns a tuple of (content, error_message). One of them will be None.
    """
    encodings_to_try = ['utf-8', 'utf-8-sig', 'utf-16', 'cp1252', 'latin-1']
    for enc in encodings_to_try:
        try:
            return file_path.read_text(encoding=enc), None
        except (UnicodeDecodeError, UnicodeError):
            continue
    try:
        # Last resort: read with replacement characters and log a warning.
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        error_msg = "Could not decode with standard encodings; read with potential data loss."
        return content, error_msg
    except Exception as e:
        return None, f"Failed to read file: {e}"

def discover_files(config: Config, log_callback: Callable[[str], None]) -> List[Path]:
    """
    Walks the directory tree ONCE to find all files matching the criteria.
    Returns a list of Path objects.
    """
    log_callback("Starting file discovery...")
    discovered_files = []
    script_path = Path(sys.argv[0]).resolve()
    output_path = (config.output_dir / config.output_filename).resolve()

    for dirpath, dirnames, filenames in os.walk(config.root_dir, topdown=True):
        # Efficiently prune the directories to search
        dirnames[:] = [d for d in dirnames if d not in config.skip_dirs]

        for filename in filenames:
            file_path = Path(dirpath) / filename

            # 1. Skip self (script or output file)
            if file_path.resolve() in (script_path, output_path):
                continue

            # 2. Check exclude patterns
            if any(fnmatch.fnmatch(filename, pattern) for pattern in config.exclude_patterns):
                continue

            # 3. Check include extensions
            if file_path.suffix.lower() in config.include_extensions:
                discovered_files.append(file_path)

    log_callback(f"Discovery complete. Found {len(discovered_files)} potential files.")
    return discovered_files

def combine_files(config: Config, files_to_process: List[Path],
                  log_callback: Callable[[str], None],
                  progress_callback: Callable[[int], None]) -> str:
    """
    Gathers files, combines them into a single text file, and returns a summary.
    This function is UI-agnostic and uses callbacks for logging and progress.
    """
    config.output_dir.mkdir(parents=True, exist_ok=True)
    output_filepath = config.output_dir / config.output_filename

    files_included_count = 0
    empty_files_count = 0
    failed_files = []
    skipped_large_files = []
    total_size_processed = 0

    try:
        with open(output_filepath, 'w', encoding='utf-8', errors='ignore') as outfile:
            log_callback(f"Output will be saved to '{output_filepath}'\n")

            for i, file_path in enumerate(files_to_process):
                progress_callback(i + 1)

                # Always use absolute path for display
                abs_path = str(file_path.resolve())
                try:
                    file_size = file_path.stat().st_size
                    if config.max_file_size_bytes and file_size > config.max_file_size_bytes:
                        skipped_large_files.append((abs_path, file_size))
                        log_callback(f"  -> SKIPPED (too large): {abs_path} ({file_size / 1024 / 1024:.2f} MB)")
                        continue

                    log_callback(f"  -> Adding: {abs_path}")
                    outfile.write(f"\n\n--- FILE: {abs_path} ---\n")
                    outfile.write("=" * 80 + "\n\n")

                    content, error = read_file_with_fallback(file_path)

                    if error:
                        log_callback(f"  -> !!! WARNING: {abs_path} | {error}")

                    if content is None:
                        failed_files.append((abs_path, error or "Unknown read error"))
                        outfile.write(f"!!! FAILED TO READ FILE. Error: {error} !!!\n")
                    elif not content.strip():
                        empty_files_count += 1
                        outfile.write("[// This file is empty or contains only whitespace. //]\n")
                    else:
                        outfile.write(content)
                        total_size_processed += file_size
                        files_included_count += 1

                except Exception as e:
                    error_message = f"Error processing file: {e}"
                    log_callback(f"  -> !!! ERROR: {abs_path} | {error_message}")
                    failed_files.append((abs_path, str(e)))

            # --- Final Summary Generation ---
            summary_lines = [
                "\n" + "=" * 50,
                " " * 15 + "SCRIPT EXECUTION SUMMARY",
                "=" * 50,
                f"Root Directory Searched: {config.root_dir}",
                f"Output File Location: {output_filepath}",
                f"Total Files Scanned: {len(files_to_process)}",
                f"Files Included in Output: {files_included_count}",
                f"Empty (or whitespace-only) Files: {empty_files_count}",
                f"Total Data Written: {total_size_processed / 1024 / 1024:.2f} MB"
            ]

            if skipped_large_files:
                summary_lines.append(f"Skipped Large Files (> {config.max_file_size_mb:.1f} MB): {len(skipped_large_files)}")
            if failed_files:
                summary_lines.append(f"Failed to Read: {len(failed_files)}")
                summary_lines.append("\n--- List of Failed Files ---")
                for f_path, err in failed_files:
                    summary_lines.append(f"  - {f_path}: {err}")
            summary_lines.append("=" * 50)

            summary_text = "\n".join(summary_lines)
            log_callback(summary_text)
            outfile.write("\n\n" + summary_text)

        return "Processing complete. See summary below."

    except IOError as e:
        return f"\nFatal Error: Could not write to output file '{output_filepath}'.\nDetails: {e}"
    except Exception as e:
        return f"\nAn unexpected fatal error occurred: {e}"


# --- GUI Application ---
if GUI_AVAILABLE:
    class ToolTip:
        """Creates a tooltip for a given widget."""
        def __init__(self, widget, text):
            self.widget = widget
            self.text = text
            self.tooltip = None
            self.widget.bind("<Enter>", self.enter)
            self.widget.bind("<Leave>", self.leave)

        def enter(self, event=None):
            x, y, _, _ = self.widget.bbox("insert")
            x += self.widget.winfo_rootx() + 25
            y += self.widget.winfo_rooty() + 25
            self.tooltip = tk.Toplevel(self.widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            label = tk.Label(self.tooltip, text=self.text, justify='left',
                             background="#ffffe0", relief="solid", borderwidth=1,
                             font=("Segoe UI", 9, "normal"))
            label.pack(ipadx=4, ipady=2)

        def leave(self, event=None):
            if self.tooltip:
                self.tooltip.destroy()
                self.tooltip = None

    class FileProcessorApp:
        def __init__(self, root_tk: tk.Tk):
            self.root = root_tk
            self.root.title("Source Code Combiner")
            self.root.geometry("900x750")
            self.root.minsize(700, 600)

            # --- Theme and Colors ---
            self.bg_color = "#2E2E2E"
            self.fg_color = "#E0E0E0"
            self.entry_bg = "#3C3F41"
            self.button_bg = "#4A4D4F"
            self.success_color = "#4CAF50"
            self.info_color = "#2196F3"
            self.error_color = "#D32F2F"
            self.text_area_bg = "#2B2B2B"

            self.root.configure(bg=self.bg_color)
            self.setup_styles()

            # --- State & Data ---
            self.config = Config()
            self.is_running = False
            self.log_queue = queue.Queue()
            self.create_variables()

            # --- UI Creation ---
            self.create_widgets()
            self.process_log_queue()

        def setup_styles(self):
            style = ttk.Style(self.root)
            style.theme_use('clam')
            style.configure("TProgressbar", thickness=15, background=self.success_color, troughcolor=self.button_bg)
            style.configure(".", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10))
            style.configure("TFrame", background=self.bg_color)
            style.configure("TLabel", background=self.bg_color, foreground=self.fg_color)
            style.configure("TCheckbutton", background=self.bg_color, foreground=self.fg_color)
            style.map("TCheckbutton", background=[('active', self.bg_color)], indicatorcolor=[('selected', self.info_color)])
            style.configure("TLabelframe", background=self.bg_color, bordercolor="#555555")
            style.configure("TLabelframe.Label", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 11, "bold"))
            style.configure("TEntry", fieldbackground=self.entry_bg, foreground=self.fg_color, bordercolor="#555555", insertcolor=self.fg_color)
            style.configure("TButton", background=self.button_bg, foreground=self.fg_color, borderwidth=0)
            style.map("TButton", background=[('active', '#5f6366')])

        def create_variables(self):
            self.root_dir_var = tk.StringVar(value=str(self.config.root_dir))
            self.output_dir_var = tk.StringVar(value=str(self.config.output_dir))
            self.output_file_var = tk.StringVar(value=self.config.output_filename)
            self.limit_size_var = tk.BooleanVar(value=self.config.limit_file_size)
            self.max_size_var = tk.StringVar(value=str(self.config.max_file_size_mb))
            self.skip_dirs_var = tk.StringVar(value=", ".join(sorted(self.config.skip_dirs)))
            self.exclude_patterns_var = tk.StringVar(value=", ".join(sorted(self.config.exclude_patterns)))
            self.include_extensions_var = tk.StringVar(value=", ".join(sorted([e.lstrip('.') for e in self.config.include_extensions])))

        def create_widgets(self):
            # --- Main container with grid layout for responsiveness ---
            main_frame = ttk.Frame(self.root, padding="15")
            main_frame.pack(fill="both", expand=True)
            main_frame.rowconfigure(2, weight=1)  # Log area expands
            main_frame.columnconfigure(0, weight=1) # All content expands horizontally

            # --- Create widget groups ---
            self.io_frame = self.create_input_output_frame(main_frame)
            self.options_frame = self.create_options_frame(main_frame)
            self.create_output_log_frame(main_frame)
            self.create_status_and_action_frame(main_frame)

            # Store widgets that need state changes
            self.input_widgets = [
                *self.io_frame.winfo_children(),
                *self.options_frame.winfo_children()
            ]

        def create_input_output_frame(self, parent):
            frame = ttk.LabelFrame(parent, text="Input & Output", padding="15")
            frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            frame.columnconfigure(1, weight=1)

            ttk.Label(frame, text="Root Directory:").grid(row=0, column=0, sticky="w", pady=5, padx=5)
            ttk.Entry(frame, textvariable=self.root_dir_var).grid(row=0, column=1, sticky="ew", pady=5, padx=5)
            ttk.Button(frame, text="Browse...", command=self.browse_root_dir).grid(row=0, column=2, sticky="e", pady=5, padx=5)

            ttk.Label(frame, text="Output Directory:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
            ttk.Entry(frame, textvariable=self.output_dir_var).grid(row=1, column=1, sticky="ew", pady=5, padx=5)
            ttk.Button(frame, text="Browse...", command=self.browse_output_dir).grid(row=1, column=2, sticky="e", pady=5, padx=5)

            ttk.Label(frame, text="Output Filename:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
            ttk.Entry(frame, textvariable=self.output_file_var).grid(row=2, column=1, sticky="ew", pady=5, padx=5)
            return frame

        def create_options_frame(self, parent):
            frame = ttk.LabelFrame(parent, text="Processing Options", padding="15")
            frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
            frame.columnconfigure(1, weight=1)

            size_frame = ttk.Frame(frame)
            size_frame.grid(row=0, column=0, columnspan=2, sticky="w", pady=2, padx=5)
            ttk.Checkbutton(size_frame, text="Limit file size. Max (MB):", variable=self.limit_size_var).pack(side="left")
            max_size_entry = ttk.Entry(size_frame, textvariable=self.max_size_var, width=8)
            max_size_entry.pack(side="left", padx=5)
            ToolTip(max_size_entry, "Set the maximum size for individual files to be included.")

            ttk.Label(frame, text="Skip Directories:").grid(row=1, column=0, sticky="w", pady=5, padx=5)
            skip_entry = ttk.Entry(frame, textvariable=self.skip_dirs_var)
            skip_entry.grid(row=1, column=1, sticky="ew", pady=5, padx=5)
            ToolTip(skip_entry, "Comma-separated list of directory names to skip entirely (e.g., node_modules, .git).")

            ttk.Label(frame, text="Exclude Patterns:").grid(row=2, column=0, sticky="w", pady=5, padx=5)
            exclude_entry = ttk.Entry(frame, textvariable=self.exclude_patterns_var)
            exclude_entry.grid(row=2, column=1, sticky="ew", pady=5, padx=5)
            ToolTip(exclude_entry, "Comma-separated list of file patterns to exclude (e.g., *.tmp, *.log). Supports wildcards.")

            ttk.Label(frame, text="Include Extensions:").grid(row=3, column=0, sticky="w", pady=5, padx=5)
            # FIX: Corrected variable name from file_extensions_var to include_extensions_var
            ext_entry = ttk.Entry(frame, textvariable=self.include_extensions_var)
            ext_entry.grid(row=3, column=1, sticky="ew", pady=5, padx=5)
            ToolTip(ext_entry, "Comma-separated list of file extensions to include (without the dot).")
            return frame

        def create_output_log_frame(self, parent):
            log_frame = ttk.LabelFrame(parent, text="Output Log", padding="15")
            log_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
            log_frame.rowconfigure(0, weight=1)
            log_frame.columnconfigure(0, weight=1)

            self.output_text = scrolledtext.ScrolledText(log_frame, wrap="word", height=15,
                                                         bg=self.text_area_bg, fg=self.fg_color,
                                                         font=("Consolas", 10), relief="flat",
                                                         borderwidth=0, state="disabled")
            self.output_text.grid(row=0, column=0, sticky="nsew")
            self.log_message("Welcome to the Source Code Combiner!\n\n"
                             "1. Configure your options above.\n"
                             "2. Click 'Start Processing' to begin.\n"
                             "3. Click 'Dump' for a quick run with current settings (no prompts).\n")

        def create_status_and_action_frame(self, parent):
            status_frame = ttk.Frame(parent)
            status_frame.grid(row=3, column=0, sticky="ew", pady=(0, 10))
            status_frame.columnconfigure(0, weight=1)

            self.progress_var = tk.DoubleVar()
            self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, mode='determinate')
            self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10))
            self.status_label = ttk.Label(status_frame, text="Ready", anchor="e")
            self.status_label.grid(row=0, column=1, sticky="e")

            action_frame = ttk.Frame(parent)
            action_frame.grid(row=4, column=0, sticky="ew")

            self.start_button = tk.Button(action_frame, text="Start Processing", command=self.start_processing,
                                          bg=self.success_color, fg="white", font=("Segoe UI", 10, "bold"),
                                          relief="flat", padx=10, pady=5, activebackground="#45a049")
            self.start_button.pack(side="left", padx=(0, 5))

            self.dump_button = tk.Button(action_frame, text="Dump", command=lambda: self.start_processing(no_prompt=True),
                                         bg=self.info_color, fg="white", font=("Segoe UI", 10, "bold"),
                                         relief="flat", padx=10, pady=5, activebackground="#1e88e5")
            self.dump_button.pack(side="left", padx=5)
            ToolTip(self.dump_button, "Quickly process using current settings, skipping any confirmation prompts.")

            self.clear_button = tk.Button(action_frame, text="Clear Log", command=self.clear_log,
                                          bg=self.button_bg, fg=self.fg_color, font=("Segoe UI", 10),
                                          relief="flat", padx=10, pady=5, activebackground="#5f6366")
            self.clear_button.pack(side="left", padx=5)

            self.exit_button = tk.Button(action_frame, text="Exit", command=self.root.destroy,
                                         bg=self.error_color, fg="white", font=("Segoe UI", 10),
                                         relief="flat", padx=10, pady=5, activebackground="#c62828")
            self.exit_button.pack(side="right")

        def browse_root_dir(self):
            directory = filedialog.askdirectory(initialdir=self.root_dir_var.get(), title="Select Root Directory")
            if directory: self.root_dir_var.set(directory)

        def browse_output_dir(self):
            directory = filedialog.askdirectory(initialdir=self.output_dir_var.get(), title="Select Output Directory")
            if directory: self.output_dir_var.set(directory)

        def log_message(self, msg: str):
            self.output_text.configure(state="normal")
            self.output_text.insert("end", msg + "\n")
            self.output_text.see("end")
            self.output_text.configure(state="disabled")

        def process_log_queue(self):
            """Process messages from the log queue in a thread-safe way."""
            try:
                while True:
                    message = self.log_queue.get_nowait()
                    self.log_message(message)
            except queue.Empty:
                pass
            finally:
                self.root.after(100, self.process_log_queue)

        def clear_log(self):
            self.output_text.configure(state="normal")
            self.output_text.delete(1.0, "end")
            self.output_text.configure(state="disabled")
            self.update_status("Log cleared.", 0)

        def update_status(self, message: str, progress_value: float):
            self.status_label.config(text=message)
            self.progress_var.set(progress_value)

        def set_ui_state(self, is_running: bool):
            self.is_running = is_running
            state = "disabled" if is_running else "normal"
            for widget in self.input_widgets:
                # This check is more robust than try/except
                if isinstance(widget, (ttk.Entry, ttk.Button, ttk.Checkbutton)):
                    widget.configure(state=state)
            self.start_button.config(state=state)
            self.dump_button.config(state=state)
            self.clear_button.config(state=state)

        def get_config_from_ui(self) -> Optional[Config]:
            """Validates UI fields and returns a Config object or None on error."""
            try:
                config = Config()
                config.root_dir = Path(self.root_dir_var.get())
                if not config.root_dir.is_dir():
                    messagebox.showerror("Error", f"Root directory not found:\n{config.root_dir}")
                    return None

                config.output_dir = Path(self.output_dir_var.get())
                config.output_filename = self.output_file_var.get()
                if not config.output_filename:
                    messagebox.showerror("Error", "Output filename cannot be empty.")
                    return None

                config.limit_file_size = self.limit_size_var.get()
                config.max_file_size_mb = float(self.max_size_var.get())
                config.skip_dirs = {d.strip() for d in self.skip_dirs_var.get().split(',') if d.strip()}
                config.exclude_patterns = {p.strip() for p in self.exclude_patterns_var.get().split(',') if p.strip()}
                config.include_extensions = {'.' + e.strip().lstrip('.') for e in self.include_extensions_var.get().split(',') if e.strip()}
                return config
            except ValueError:
                messagebox.showerror("Error", "Invalid 'Max size (MB)'. Please enter a valid number.")
                return None
            except Exception as e:
                messagebox.showerror("Configuration Error", f"An unexpected error occurred while reading settings:\n{e}")
                return None

        def start_processing(self, no_prompt=False):
            if self.is_running: return

            config = self.get_config_from_ui()
            if not config: return

            output_filepath = config.output_dir / config.output_filename
            if output_filepath.exists() and not no_prompt:
                if not messagebox.askyesno("Confirm Overwrite", f"The file '{output_filepath.name}' already exists.\nDo you want to overwrite it?"):
                    self.update_status("Operation cancelled.", 0)
                    return

            self.set_ui_state(is_running=True)
            self.output_text.configure(state="normal")
            self.output_text.delete(1.0, "end")
            self.output_text.configure(state="disabled")

            threading.Thread(target=self.process_files_thread, args=(config,), daemon=True).start()

        def process_files_thread(self, config: Config):
            try:
                # Thread-safe callbacks using the queue and root.after
                def log_to_queue(msg): self.log_queue.put(msg)
                def progress_on_main_thread(val): self.root.after(0, self.update_status, f"Processing... {val}/{total_files}", val)

                files_to_process = discover_files(config, log_to_queue)
                total_files = len(files_to_process)
                self.root.after(0, self.progress_bar.config, {'maximum': total_files if total_files > 0 else 100})

                combine_files(config, files_to_process, log_to_queue, progress_on_main_thread)

                self.root.after(0, self.update_status, "Complete!", self.progress_bar['maximum'])
                self.root.after(0, messagebox.showinfo, "Success", "File processing completed successfully!")
            except Exception as e:
                self.log_queue.put(f"\nFATAL ERROR in processing thread: {e}")
                self.root.after(0, self.update_status, "Error!", self.progress_var.get())
                self.root.after(0, messagebox.showerror, "Processing Error", f"An unexpected error occurred:\n{e}")
            finally:
                self.root.after(0, self.set_ui_state, False)

def main():
    """Main function to parse arguments and run either CLI or GUI."""
    parser = argparse.ArgumentParser(
        description="Combine source code files into a single text file.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--no-gui', action='store_true', help="Force command-line mode, even if GUI is available.")
    parser.add_argument('--root', type=str, help="Root directory to search.")
    parser.add_argument('--output', type=str, help="Output filename.")
    parser.add_argument('--outdir', type=str, help="Output directory.")
    parser.add_argument('--no-prompt', action='store_true', help="Do not prompt for overwriting files in CLI mode.")
    parser.add_argument('--skip-dirs', type=str, help="Comma-separated list of directories to skip.")
    parser.add_argument('--exclude', type=str, help="Comma-separated list of file patterns to exclude.")
    args = parser.parse_args()

    # --- GUI Mode ---
    if not args.no_gui and GUI_AVAILABLE:
        root = tk.Tk()
        app = FileProcessorApp(root)
        root.mainloop()
        return

    # --- Command-Line Mode ---
    if not GUI_AVAILABLE:
        print("Tkinter not found. Running in command-line mode.")
    print("Running in command-line mode...")
    start_time = time.time()

    config = Config()
    if args.root: config.root_dir = Path(args.root)
    if args.output: config.output_filename = args.output
    if args.outdir: config.output_dir = Path(args.outdir)
    if args.skip_dirs: config.skip_dirs = {d.strip() for d in args.skip_dirs.split(',')}
    if args.exclude: config.exclude_patterns = {p.strip() for p in args.exclude.split(',')}

    output_filepath = config.output_dir / config.output_filename
    if output_filepath.exists() and not args.no_prompt:
        response = input(f"Output file '{output_filepath}' already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Operation cancelled by user.")
            return

    def cli_log(msg): print(msg)
    def cli_progress(count): pass # Simple CLI has no progress bar

    files = discover_files(config, cli_log)
    summary = combine_files(config, files, cli_log, cli_progress)

    print(f"\n{summary}")
    print(f"Total execution time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()