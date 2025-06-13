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
        self.configure(bg="#000000")

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#000000")
        style.configure("TLabel", background="#000000", foreground="#d0d0d0")
        style.configure("TButton", background="#333333", foreground="#ffffff")
        style.configure("TEntry", fieldbackground="#333333", foreground="#ffffff")

        self.cmd_var = tk.StringVar(value="./libero_validator")
        self.args_var = tk.StringVar()
        self.process = None
        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, style="TFrame")
        frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(frame, text="Command:", style="TLabel").pack(side='left')
        ttk.Entry(frame, textvariable=self.cmd_var, width=40, style="TEntry").pack(side='left', fill='x', expand=True)
        ttk.Button(frame, text="Browse", command=self.browse_cmd, style="TButton").pack(side='left', padx=5)

        args_frame = ttk.Frame(self, style="TFrame")
        args_frame.pack(fill='x', padx=10)
        ttk.Label(args_frame, text="Arguments:", style="TLabel").pack(side='left')
        ttk.Entry(args_frame, textvariable=self.args_var, width=40, style="TEntry").pack(side='left', fill='x', expand=True)

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
