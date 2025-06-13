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
        self.configure(bg="#e0e0e0")

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#e0e0e0")
        style.configure("TLabel", background="#e0e0e0")

        self.cmd_var = tk.StringVar(value="./libero_validator")
        self.args_var = tk.StringVar()
        self.process = None
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self)
        frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(frame, text="Command:").pack(side='left')
        ttk.Entry(frame, textvariable=self.cmd_var, width=40).pack(side='left', fill='x', expand=True)
        ttk.Button(frame, text="Browse", command=self.browse_cmd).pack(side='left', padx=5)

        args_frame = ttk.Frame(self)
        args_frame.pack(fill='x', padx=10)
        ttk.Label(args_frame, text="Arguments:").pack(side='left')
        ttk.Entry(args_frame, textvariable=self.args_var, width=40).pack(side='left', fill='x', expand=True)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill='x', padx=10, pady=10)
        ttk.Button(btn_frame, text="Run", command=self.run_cmd).pack(side='left')
        ttk.Button(btn_frame, text="Stop", command=self.stop_cmd).pack(side='left', padx=5)
        output_frame = ttk.Frame(self)
        output_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.output = tk.Text(output_frame, state='disabled', wrap='word', bg='#f8f8f8')
        scrollbar = ttk.Scrollbar(output_frame, command=self.output.yview)
        self.output.configure(yscrollcommand=scrollbar.set)
        self.output.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

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
