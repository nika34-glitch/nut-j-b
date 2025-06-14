"""
Simple Tkinter front-end for running the validator or any CLI.
"""
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import subprocess
import threading

class CLIFrontend(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Analysis Tool GUI")
        self.geometry("600x400")
        self.configure(bg="#333333")

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#333333")
        style.configure("TLabel", background="#333333", foreground="#d0d0d0")
        style.configure("TButton", background="#000000", foreground="#ffffff")
        style.configure(
            "TEntry", fieldbackground="#000000", foreground="#ffffff"
        )
        style.map("TButton", background=[("active", "#111111")])

        self.cmd_var = tk.StringVar(value="./libero_validator")
        self.conc_var = tk.IntVar(value=3000)
        self.timeout_var = tk.DoubleVar(value=10.0)
        self.retries_var = tk.IntVar(value=0)
        self.poponly_var = tk.BooleanVar()
        self.full_var = tk.BooleanVar()
        self.refresh_var = tk.DoubleVar(value=1.0)
        self.free_var = tk.BooleanVar()
        self.fast_open_var = tk.BooleanVar()
        self.ui_var = tk.BooleanVar()
        self.shards_var = tk.IntVar(value=1)
        self.backend_var = tk.StringVar()
        self.rps_var = tk.IntVar(value=15)
        self.quarantine_var = tk.IntVar(value=60)
        self.latency_weight_var = tk.DoubleVar(value=1.0)
        self.ban_weight_var = tk.DoubleVar(value=1.5)
        self.process = None
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, style="TFrame")
        frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(frame, text="Command:", style="TLabel").pack(side='left')
        ttk.Entry(frame, textvariable=self.cmd_var, width=40, style="TEntry").pack(side='left', fill='x', expand=True)
        ttk.Button(frame, text="Browse", command=self.browse_cmd, style="TButton").pack(side='left', padx=5)

        args_frame = ttk.LabelFrame(self, text="Options", style="TFrame")
        args_frame.pack(fill='x', padx=10)
        ttk.Label(args_frame, text="Concurrency", style="TLabel").grid(row=0, column=0, sticky='w')
        ttk.Spinbox(args_frame, from_=1, to=10000, textvariable=self.conc_var, width=7).grid(row=0, column=1, sticky='w')
        ttk.Label(args_frame, text="Timeout", style="TLabel").grid(row=0, column=2, sticky='w')
        ttk.Spinbox(args_frame, from_=1, to=60, textvariable=self.timeout_var, width=7).grid(row=0, column=3, sticky='w')
        ttk.Label(args_frame, text="Retries", style="TLabel").grid(row=0, column=4, sticky='w')
        ttk.Spinbox(args_frame, from_=0, to=10, textvariable=self.retries_var, width=5).grid(row=0, column=5, sticky='w')
        ttk.Checkbutton(args_frame, text="POP only", variable=self.poponly_var).grid(row=1, column=0, sticky='w')
        ttk.Checkbutton(args_frame, text="Full", variable=self.full_var).grid(row=1, column=1, sticky='w')
        ttk.Checkbutton(args_frame, text="Auto Proxy", variable=self.free_var).grid(row=1, column=2, sticky='w')
        ttk.Checkbutton(args_frame, text="Fast Open", variable=self.fast_open_var).grid(row=1, column=3, sticky='w')
        ttk.Checkbutton(args_frame, text="Terminal UI", variable=self.ui_var).grid(row=1, column=4, sticky='w')
        ttk.Label(args_frame, text="Shards", style="TLabel").grid(row=2, column=0, sticky='w')
        ttk.Spinbox(args_frame, from_=1, to=32, textvariable=self.shards_var, width=5).grid(row=2, column=1, sticky='w')
        ttk.Label(args_frame, text="Refresh", style="TLabel").grid(row=2, column=2, sticky='w')
        ttk.Spinbox(args_frame, from_=0, to=10, increment=0.1, textvariable=self.refresh_var, width=7).grid(row=2, column=3, sticky='w')
        ttk.Label(args_frame, text="Backend", style="TLabel").grid(row=3, column=0, sticky='w')
        ttk.Entry(args_frame, textvariable=self.backend_var, width=12, style="TEntry").grid(row=3, column=1, sticky='w')
        ttk.Label(args_frame, text="Requests per Second", style="TLabel").grid(row=3, column=2, sticky='w')
        ttk.Spinbox(args_frame, from_=1, to=100, textvariable=self.rps_var, width=5).grid(row=3, column=3, sticky='w')
        ttk.Label(args_frame, text="Quarantine", style="TLabel").grid(row=3, column=4, sticky='w')
        ttk.Spinbox(args_frame, from_=0, to=3600, textvariable=self.quarantine_var, width=7).grid(row=3, column=5, sticky='w')
        ttk.Label(args_frame, text="Latency Weight", style="TLabel").grid(row=4, column=0, sticky='w')
        latency_scale = ttk.Scale(args_frame, from_=0.1, to=5.0, orient='horizontal', variable=self.latency_weight_var, command=self.update_latency_label)
        latency_scale.grid(row=4, column=1, sticky='ew')
        self.latency_val_lbl = ttk.Label(args_frame, text=f"{self.latency_weight_var.get():.1f}")
        self.latency_val_lbl.grid(row=4, column=2, sticky='w')
        ttk.Label(args_frame, text="Ban Weight", style="TLabel").grid(row=4, column=3, sticky='w')
        ban_scale = ttk.Scale(args_frame, from_=0.1, to=5.0, orient='horizontal', variable=self.ban_weight_var, command=self.update_ban_label)
        ban_scale.grid(row=4, column=4, sticky='ew')
        self.ban_val_lbl = ttk.Label(args_frame, text=f"{self.ban_weight_var.get():.1f}")
        self.ban_val_lbl.grid(row=4, column=5, sticky='w')

        btn_frame = ttk.Frame(self, style="TFrame")
        btn_frame.pack(fill='x', padx=10, pady=10)
        ttk.Button(btn_frame, text="Run", command=self.run_cmd, style="TButton").pack(side='left')
        ttk.Button(btn_frame, text="Stop", command=self.stop_cmd, style="TButton").pack(side='left', padx=5)
        output_frame = ttk.Frame(self, style="TFrame")
        output_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.output = tk.Text(output_frame, state='disabled', wrap='word', bg='#000000', fg='#d0d0d0', insertbackground='#d0d0d0')
        scrollbar = ttk.Scrollbar(output_frame, command=self.output.yview)
        self.output.configure(yscrollcommand=scrollbar.set)
        self.output.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        stats_frame = ttk.Frame(self, style="TFrame")
        stats_frame.pack(fill='x', padx=10, pady=(0,10))
        self.progress = ttk.Progressbar(stats_frame, length=200)
        self.progress.grid(row=0, column=0, columnspan=5, sticky='ew', pady=2)
        self.progress_lbl = ttk.Label(stats_frame, text="0%")
        self.progress_lbl.grid(row=0, column=5, sticky='w')
        self.total_lbl = ttk.Label(stats_frame, text="Total 0")
        self.total_lbl.grid(row=1, column=0, sticky='w')
        self.checked_lbl = ttk.Label(stats_frame, text="Checked 0")
        self.checked_lbl.grid(row=1, column=1, sticky='w')
        self.valid_lbl = ttk.Label(stats_frame, text="Valid 0", foreground='lightgreen')
        self.valid_lbl.grid(row=1, column=2, sticky='w')
        self.invalid_lbl = ttk.Label(stats_frame, text="Invalid 0", foreground='red')
        self.invalid_lbl.grid(row=1, column=3, sticky='w')
        self.errors_lbl = ttk.Label(stats_frame, text="Errors 0")
        self.errors_lbl.grid(row=1, column=4, sticky='w')
        self.eta_lbl = ttk.Label(stats_frame, text="Time Remaining ?")
        self.eta_lbl.grid(row=1, column=5, sticky='w')

    def browse_cmd(self):
        path = filedialog.askopenfilename(title="Select executable")
        if path:
            self.cmd_var.set(path)

    def run_cmd(self):
        if self.process:
            messagebox.showwarning("Running", "Process already running")
            return
        cmd = [self.cmd_var.get()]
        if self.conc_var.get():
            cmd += ["--conc", str(self.conc_var.get())]
        if self.timeout_var.get():
            cmd += ["--timeout", str(self.timeout_var.get())]
        if self.retries_var.get():
            cmd += ["--retries", str(self.retries_var.get())]
        if self.poponly_var.get():
            cmd.append("--poponly")
        if self.full_var.get():
            cmd.append("--full")
        if self.refresh_var.get():
            cmd += ["--refresh", str(self.refresh_var.get())]
        if self.free_var.get():
            cmd.append("--auto-proxy")
        if self.backend_var.get():
            cmd += ["--free-backend", self.backend_var.get()]
        if self.rps_var.get() != 15:
            cmd += ["--free-rps", str(self.rps_var.get())]
        if self.quarantine_var.get() != 60:
            cmd += ["--free-quarantine", str(self.quarantine_var.get())]
        if self.latency_weight_var.get() != 1.0:
            cmd += ["--free-latency-weight", str(self.latency_weight_var.get())]
        if self.ban_weight_var.get() != 1.5:
            cmd += ["--free-ban-weight", str(self.ban_weight_var.get())]
        if self.fast_open_var.get():
            cmd.append("--fast-open")
        if self.ui_var.get():
            cmd.append("--ui")
        if self.shards_var.get() != 1:
            cmd += ["--shards", str(self.shards_var.get())]
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
                    self.update_stats(line)
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
        self.output.after(0, self._append_output, text)

    def _append_output(self, text):
        self.output.config(state='normal')
        self.output.insert(tk.END, text)
        self.output.see(tk.END)
        self.output.config(state='disabled')

    def update_latency_label(self, value):
        try:
            self.latency_val_lbl.config(text=f"{float(value):.1f}")
        except Exception:
            pass

    def update_ban_label(self, value):
        try:
            self.ban_val_lbl.config(text=f"{float(value):.1f}")
        except Exception:
            pass

    def update_stats(self, line: str):
        if not line.startswith("tot:"):
            return
        parts = {}
        for item in line.strip().split():
            if ":" in item:
                k, v = item.split(":", 1)
                parts[k] = v

        try:
            self.total_lbl.config(text=f"Total {parts.get('tot','?')}")
            self.checked_lbl.config(text=f"Checked {parts.get('chk','?')}")
            self.valid_lbl.config(text=f"Valid {parts.get('ok','?')}")
            self.invalid_lbl.config(text=f"Invalid {parts.get('bad','?')}")
            self.errors_lbl.config(text=f"Errors {parts.get('err','?')}")
            self.eta_lbl.config(text=f"Time Remaining {parts.get('eta','?')}")
            if 'prog' in parts:
                try:
                    progress_val = float(parts.get('prog', 0))
                    self.progress['value'] = progress_val
                    self.progress_lbl.config(text=f"{progress_val:.1f}%")
                except Exception:
                    pass
        except Exception:
            pass

if __name__ == '__main__':
    app = CLIFrontend()
    app.mainloop()
