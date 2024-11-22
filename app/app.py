import os
import subprocess
import time
import datetime
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from watchdog.observers import Observer # type: ignore
from watchdog.events import FileSystemEventHandler # type: ignore

# Paths to the files and Squid executable
FILE_TO_WATCH = r"D:\Squid\etc\squid\blocked_domains.txt"
ACCESS_LOG_PATH = r"D:\Squid\var\log\squid\access.log"
SQUID_EXECUTABLE = r"D:\Squid\bin\squid.exe"
SQUID_CONFIG = r"D:\Squid\etc\squid\squid.conf"

# Function to start Squid manually
def start_squid():
    print("Starting Squid...")
    return subprocess.Popen([SQUID_EXECUTABLE, '-N', '-d1'])

# Function to stop Squid by terminating the process
def stop_squid(process):
    print("Stopping Squid...")
    process.terminate()
    process.wait()

# Function to read and parse Squid's access.log with formatted timestamp
def read_access_log():
    log_entries = []
    if os.path.exists(ACCESS_LOG_PATH):
        with open(ACCESS_LOG_PATH, 'r') as log_file:
            lines = log_file.readlines()[-15:]  # Last 10 entries for brevity
            for line in lines:
                parts = line.split()
                if len(parts) > 7:
                    timestamp = datetime.datetime.fromtimestamp(float(parts[0])).strftime('%Y-%m-%d %H:%M:%S')
                    client_ip = parts[2]
                    action = parts[3]
                    url = parts[6]
                    log_entries.append((timestamp, client_ip, action, url))
    return log_entries

# Event handler for file changes
class FileChangeHandler(FileSystemEventHandler):
    def __init__(self):
        self.squid_process = start_squid()

    def on_modified(self, event):
        if event.src_path == FILE_TO_WATCH:
            print(f"Detected change in {FILE_TO_WATCH}")
            stop_squid(self.squid_process)
            self.squid_process = start_squid()
    def on_modified_config(self, event):
        if event.src_path == SQUID_CONFIG:
            print(f"Detected change in {SQUID_CONFIG}")
            stop_squid(self.squid_process)
            self.squid_process = start_squid()

# GUI class for displaying logs
class LogMonitorUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Squid Access Log Monitor")

        # Scrolled text widget for displaying access log entries in table format
        self.log_display = ScrolledText(root, width=100, height=20, state='disabled', wrap='none')
        self.log_display.pack(padx=10, pady=10)

        # Start file monitoring
        self.event_handler = FileChangeHandler()
        self.observer = Observer()
        self.observer.schedule(self.event_handler, os.path.dirname(FILE_TO_WATCH), recursive=False)
        self.observer.start()

        # Periodic log update
        self.update_logs()

    # Function to update log display with table formatting
    def update_logs(self):
        log_entries = read_access_log()
        self.log_display.config(state='normal')
        self.log_display.delete(1.0, tk.END)  # Clear previous log

        # Header for the table
        header = f"{'Time':<20} | {'Client IP':<15} | {'Action':<10} | {'URL'}\n"
        self.log_display.insert(tk.END, header)
        self.log_display.insert(tk.END, "-" * 80 + "\n")

        # Insert log entries
        for entry in log_entries:
            timestamp, client_ip, action, url = entry
            row = f"{timestamp:<20} | {client_ip:<15} | {action:<10} | {url}\n"
            self.log_display.insert(tk.END, row)

        self.log_display.config(state='disabled')
        self.root.after(5000, self.update_logs)  # Update every 5 seconds

    def on_close(self):
        self.observer.stop()
        self.observer.join()
        stop_squid(self.event_handler.squid_process)
        self.root.destroy()

# Main function to initialize the UI and monitoring
def main():
    root = tk.Tk()
    app = LogMonitorUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close) 
    root.mainloop()

if __name__ == "__main__":
    main()