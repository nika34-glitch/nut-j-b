"""Minimal Tkinter GUI for running the validator or any command line tool."""

import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk


BG_COLOR = "#f0f0f0"

class CLIFrontend(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Libero Validator")
        self.geometry("650x420")
        self.configure(bg=BG_COLOR)

        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TButton", padding=5)

        self.cmd_var = tk.StringVar(value="./libero_validator")
        self.args_var = tk.StringVar()
        self.process = None

        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self)
        frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 5))

        ttk.Label(frame, text="Command:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.cmd_var, width=45).grid(row=0, column=1, sticky="ew")
        ttk.Button(frame, text="Browse", command=self.browse_cmd).grid(row=0, column=2, padx=5)
        frame.columnconfigure(1, weight=1)

        args_frame = ttk.Frame(self)
        args_frame.grid(row=1, column=0, sticky="ew", padx=10)
        ttk.Label(args_frame, text="Arguments:").grid(row=0, column=0, sticky="w")
        ttk.Entry(args_frame, textvariable=self.args_var, width=45).grid(row=0, column=1, sticky="ew")
        args_frame.columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, column=0, sticky="w", padx=10, pady=5)
        ttk.Button(btn_frame, text="Run", command=self.run_cmd).pack(side="left")
        ttk.Button(btn_frame, text="Stop", command=self.stop_cmd).pack(side="left", padx=5)

        self.output = scrolledtext.ScrolledText(
            self, state="disabled", wrap="word", height=15
        )
        self.output.grid(row=3, column=0, sticky="nsew", padx=10, pady=5)

        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def browse_cmd(self):
        path = filedialog.askopenfilename(title="Select executable")
        if path:
            self.cmd_var.set(path)

    def run_cmd(self):
        if self.process:
            messagebox.showwarning("Running", "Process already running")
            return
        cmd = [self.cmd_var.get()] + self.args_var.get().split()
        self.output.config(state='normal')
        self.output.delete('1.0', tk.END)
        self.output.config(state='disabled')
        def target():
            try:
                self.process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                for line in self.process.stdout:
                    self.append_output(line)
            except FileNotFoundError:
                self.append_output("Command not found\n")
            finally:
                self.process = None
        threading.Thread(target=target, daemon=True).start()

    def stop_cmd(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.append_output("\nProcess terminated\n")
        else:
            messagebox.showinfo("Not running", "No process to stop")

    def append_output(self, text):
        self.output.config(state='normal')
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.config(state='disabled')

if __name__ == '__main__':
    app = CLIFrontend()
    app.mainloop()
