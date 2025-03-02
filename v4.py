import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import threading
import pandas as pd

CVE_SEARCH_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="


class CyberSentinel:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberSentinel v1.4 - Next-Level CVE Search Tool")
        self.root.geometry("1200x700")
        self.root.minsize(800, 500)
        self.root.configure(bg="#1c1c1c")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#1c1c1c")
        self.style.configure("TLabel", background="#1c1c1c", foreground="#00ff00", font=("Courier", 14, "bold"))
        self.style.configure("TButton", background="#282828", foreground="#00ff00", font=("Courier", 12, "bold"))
        self.style.configure("Treeview", background="#1e1e1e", foreground="white", fieldbackground="#1e1e1e",
                             font=("Courier", 12))
        self.style.map("TButton", background=[("active", "#444444")])

        self.cve_data = []
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.root, text="CyberSentinel v1.4", font=("Courier", 18, "bold"), foreground="#00ff00").pack(pady=10)

        # Centered Search Row
        frame = ttk.Frame(self.root)
        frame.pack(pady=10)

        ttk.Label(frame, text="Search CVEs:").grid(row=0, column=0, padx=5, pady=5)
        self.search_entry = ttk.Entry(frame, width=30)
        self.search_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Search", command=self.search_cves).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame, text="From Year:").grid(row=0, column=3, padx=5, pady=5)
        self.year_from = ttk.Entry(frame, width=10)
        self.year_from.grid(row=0, column=4, padx=5, pady=5)

        ttk.Label(frame, text="To Year:").grid(row=0, column=5, padx=5, pady=5)
        self.year_to = ttk.Entry(frame, width=10)
        self.year_to.grid(row=0, column=6, padx=5, pady=5)

        # Frame for Treeview and Scrollbar
        table_frame = ttk.Frame(self.root)
        table_frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=10)

        self.tree = ttk.Treeview(table_frame, columns=("CVE ID", "Severity", "Description"), show='headings')
        self.tree.heading("CVE ID", text="CVE ID")
        self.tree.heading("Severity", text="Severity")
        self.tree.heading("Description", text="Description")
        self.tree.column("CVE ID", width=150)
        self.tree.column("Severity", width=120)
        self.tree.column("Description", width=900)

        # Scrollbar
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Bind double-click event to show CVE details
        self.tree.bind("<Double-1>", self.show_cve_details)

        # Export Button
        ttk.Button(self.root, text="Export Data to CSV", command=self.export_csv).pack(pady=10)

    def search_cves(self):
        query = self.search_entry.get()
        year_from = self.year_from.get()
        year_to = self.year_to.get()

        if not query:
            messagebox.showwarning("Input Error", "Please enter a search term!")
            return

        threading.Thread(target=self.fetch_cves, args=(query, year_from, year_to), daemon=True).start()

    def fetch_cves(self, query, year_from, year_to):
        try:
            response = requests.get(f"{CVE_SEARCH_URL}{query}")
            data = response.json()

            if "vulnerabilities" not in data:
                messagebox.showwarning("No Results", "No CVEs found for the given query.")
                return

            self.cve_data = []
            for item in data["vulnerabilities"]:
                cve_id = item["cve"]["id"]
                severity = item["cve"].get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get(
                    "baseSeverity", "Unknown")
                description = next(
                    (desc["value"] for desc in item["cve"].get("descriptions", []) if desc["lang"] == "en"),
                    "No description available")
                publish_date = item["cve"].get("published", "")[:4]

                if (not year_from or publish_date >= year_from) and (not year_to or publish_date <= year_to):
                    self.cve_data.append((cve_id, severity, description))

            self.update_results()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch data: {e}")

    def update_results(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for item in self.cve_data:
            self.tree.insert("", "end", values=item)

    def show_cve_details(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        cve_id, severity, description = self.tree.item(selected_item[0])["values"]

        # Create a pop-up window
        popup = tk.Toplevel(self.root)
        popup.title(f"CVE Details - {cve_id}")
        popup.geometry("600x400")
        popup.configure(bg="#1c1c1c")

        ttk.Label(popup, text=f"CVE ID: {cve_id}", font=("Courier", 14, "bold"), foreground="#00ff00").pack(pady=5)
        ttk.Label(popup, text=f"Severity: {severity}", font=("Courier", 12), foreground="#ff6600").pack(pady=5)

        description_frame = tk.Frame(popup, bg="#1c1c1c")
        description_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        description_text = tk.Text(description_frame, wrap=tk.WORD, bg="#1c1c1c", fg="white", font=("Courier", 12))
        description_text.insert(tk.END, description)
        description_text.config(state=tk.DISABLED)  # Make text read-only
        description_text.pack(fill=tk.BOTH, expand=True)

        # Copy Button
        ttk.Button(popup, text="Copy CVE ID", command=lambda: self.copy_to_clipboard(cve_id)).pack(pady=10)

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", f"{text} copied to clipboard.")

    def export_csv(self):
        if not self.cve_data:
            messagebox.showwarning("Export Error", "No data available to export!")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return

        df = pd.DataFrame(self.cve_data, columns=["CVE ID", "Severity", "Description"])
        df.to_csv(file_path, index=False)
        messagebox.showinfo("Export Success", "Data successfully exported to CSV!")


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberSentinel(root)
    root.mainloop()
