import requests
from bs4 import BeautifulSoup
import warnings
from urllib.parse import urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

def run_csrf_test(url):
    results = []
    results.append("------------------------------------------------------")
    results.append("[=] CSRF (Cross-Site Request Forgery) testi başlatılıyor...")
    results.append("------------------------------------------------------")

    try:
        response = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            results.append("[~] Sayfada analiz edilecek form bulunamadı.")
        else:
            results.append(f"[+] {len(forms)} form bulundu. CSRF koruması kontrol ediliyor...")

        risky_forms = 0

        for i, form in enumerate(forms, 1):
            action = form.get("action", "yok")
            method = form.get("method", "get").upper()
            inputs = form.find_all("input")

            input_names = [inp.get("name", "").lower() for inp in inputs if inp.get("name")]
            token_like = [name for name in input_names if any(word in name for word in ["csrf", "token", "auth"])]

            results.append(f"\n--- Form {i} Bilgisi ---")
            results.append(f"ACTION: {action}")
            results.append(f"METHOD: {method}")
            results.append(f"INPUT SAYISI: {len(inputs)}")
            results.append(f"INPUT İSİMLERİ: {', '.join(input_names) if input_names else 'YOK'}")

            if token_like:
                results.append(f"[+] CSRF koruma tokenı bulundu: {', '.join(token_like)}")
            else:
                results.append(f"[!] CSRF token bulunamadı. Zafiyet ihtimali var!")
                risky_forms += 1

    except Exception as e:
        results.append(f"[X] CSRF testi sırasında hata oluştu: {e}")

    results.append("\n------------------------------------------------------")
    results.append(f"[=] CSRF testi tamamlandı. Riskli form sayısı: {risky_forms}")
    results.append("------------------------------------------------------")

    return "\n".join(results)

if __name__ == "__main__":
    hedef_url = input("Test edilecek URL: ")
    print(run_csrf_test(hedef_url))
