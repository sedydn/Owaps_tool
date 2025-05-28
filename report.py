import os
from datetime import datetime
from urllib.parse import urlparse

def save_report(url, test_results):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname or "rapor"
    filename = f"{domain}_rapor.txt"

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    filepath = os.path.join(desktop, filename)

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("###########################\n")
            f.write("# OWASP ZAFİYET RAPORU   #\n")
            f.write("###########################\n\n")
            f.write(f"Tarih: {datetime.now().strftime('%d.%m.%Y - %H:%M:%S')}\n")
            f.write(f"Test Edilen Adres: {url}\n\n")

            for title, content in test_results.items():
                f.write("------------------------------------------------------\n")
                f.write(f"[=] {title.upper()} Sonuçları\n")
                f.write("------------------------------------------------------\n")
                f.write(content.strip() + "\n\n")

            # 📌 Tarama Özeti & Yorumlar
            f.write("###########################\n")
            f.write("📌 Tarama Özeti & Güvenlik Değerlendirmesi\n")
            f.write("###########################\n\n")

            f.write("Tespit Edilen Zafiyetler:\n")

            # Bayraklar
            xss_flag = "açığı bulundu" in test_results.get("XSS", "").lower()
            sql_flag = "açığı bulundu" in test_results.get("SQL Injection", "").lower()
            ssl_expired = "süresi dolmuş" in test_results.get("SSL", "").lower()
            ssl_soon = "yakında sona erecek" in test_results.get("SSL", "").lower()
            headers_flag = "eksik" in test_results.get("Headers", "").lower()

            if xss_flag:
                f.write("- ✅ XSS açığı bulundu.\n")
            else:
                f.write("- ✅ XSS testi geçti.\n")

            if sql_flag:
                f.write("- ✅ SQL Injection zafiyeti tespit edildi.\n")
            else:
                f.write("- ✅ SQL Injection testi geçti.\n")

            if headers_flag:
                f.write("- ⚠️ Güvenlik başlıkları eksik veya eksik olabilir.\n")
            else:
                f.write("- ✅ HTTP başlıkları uygun.\n")

            if ssl_expired:
                f.write("- ❌ SSL sertifikası süresi dolmuş!\n")
            elif ssl_soon:
                f.write("- ⚠️ SSL sertifikası çok yakında sona erecek.\n")
            else:
                f.write("- ✅ SSL sertifikası geçerli ve güncel.\n")

            # --- Yorum ---
            f.write("\nYorum:\n")
            if xss_flag or sql_flag:
                f.write("Tarama sırasında kritik OWASP zafiyetleri (XSS ve/veya SQL Injection) tespit edilmiştir. "
                        "Bu açıklar saldırganlara sistem üzerinde veri çalma, oturum ele geçirme, kod çalıştırma gibi yetkiler kazandırabilir.\n")
            else:
                f.write("Tarama sonuçlarına göre kritik OWASP zafiyeti bulunmamıştır. Ancak sistemin güvenliği için düzenli test önerilir.\n")

            if ssl_expired or ssl_soon:
                f.write("SSL sertifikasında tarihsel bir sorun tespit edilmiştir. İletişim güvenliği riske girebilir.\n")

            if headers_flag:
                f.write("HTTP başlıklarında eksiklikler bulunmuştur. Tarayıcı korumaları aktif olmayabilir.\n")

            # --- Öneriler ---
            f.write("\nÖneriler:\n")
            if xss_flag:
                f.write("- XSS: Kullanıcı girdileri encode edilmeli ve zararlı JS filtrelenmelidir.\n")
            if sql_flag:
                f.write("- SQL Injection: Parametrik sorgular ve input doğrulama zorunludur.\n")
            if ssl_expired or ssl_soon:
                f.write("- SSL: Sertifika yenilenmeli ve otomatikleştirilmelidir.\n")
            if headers_flag:
                f.write("- Headers: X-Frame-Options, Content-Security-Policy gibi başlıklar eklenmelidir.\n")

            f.write("\nBu rapor, temel OWASP güvenlik kontrollerine göre otomatik oluşturulmuştur.\n")

        return filepath

    except Exception as e:
        return f"Hata oluştu: {e}"

# Örnek kullanım (isteğe bağlı):
if __name__ == "__main__":
    example_results = {
        "XSS": "XSS açığı bulundu!",
        "SQL Injection": "SQL Injection zafiyeti tespit edildi!",
        "SSL": "SSL sertifikası geçerli ama yakında sona erecek.",
        "Headers": "Bazı güvenlik başlıkları eksik olabilir."
    }
    path = save_report("https://www.example.com", example_results)
    print(f"Rapor kaydedildi: {path}")
