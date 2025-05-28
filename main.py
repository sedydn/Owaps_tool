import tkinter as tk
from tkinter import messagebox, ttk
import os
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from xss import run_xss_test
from sql import run_sql_test
from headers import run_header_test
from ssl_check import run_ssl_check
from report import save_report

warnings.simplefilter("ignore", InsecureRequestWarning)

class OwaspToolGUI:
    def __init__(self, master):
        self.master = master
        master.title("OWASP Tool - Zafiyet Tarayıcı")

        self.url_label = tk.Label(master, text="URL Giriniz (http/https ile):")
        self.url_label.pack()

        self.url_entry = tk.Entry(master, width=60)
        self.url_entry.pack(pady=5)

        self.scan_button = tk.Button(master, text="Tarama Başlat", command=self.start_scan)
        self.scan_button.pack(pady=10)

        self.result_text = tk.Text(master, height=30, width=100, bg="black", fg="lime", font=("Consolas", 10))
        self.result_text.pack(padx=10, pady=10)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            messagebox.showerror("Hata", "Lütfen geçerli bir URL girin (http:// veya https:// ile)")
            return

        self.result_text.delete(1.0, tk.END)
        self.log(f"[=] Tarama başlatılıyor: {url}")
        test_results = {}

        try:
            self.log("\n[~] XSS testi başlatılıyor...")
            xss_result = run_xss_test(url)
            test_results["XSS"] = xss_result
            self.log(xss_result)

            self.log("\n[~] SQL Injection testi başlatılıyor...")
            sql_result = run_sql_test(url)
            test_results["SQL Injection"] = sql_result
            self.log(sql_result)

            self.log("\n[~] Header testi başlatılıyor...")
            header_result = run_header_test(url)
            test_results["Headers"] = header_result
            self.log(header_result)

            self.log("\n[~] SSL kontrolü başlatılıyor...")
            ssl_result = run_ssl_check(url)
            test_results["SSL"] = ssl_result
            self.log(ssl_result)

            self.log("\n[~] Rapor oluşturuluyor...")
            report_path = save_report(url, test_results)
            self.log(f"[✓] Rapor başarıyla oluşturuldu: {report_path}")
            messagebox.showinfo("Tarama Tamamlandı", f"Rapor masaüstüne kaydedildi:\n{report_path}")

        except Exception as e:
            self.log(f"[X] Tarama sırasında hata oluştu: {e}")
            messagebox.showerror("Hata", str(e))

    def log(self, message):
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = OwaspToolGUI(root)
    root.mainloop()
