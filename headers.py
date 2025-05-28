import requests
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "XSS ve veri enjeksiyonlarına karşı savunma sağlar.",
        "should_contain": "default-src",
        "recommendation": "default-src 'self';"
    },
    "Strict-Transport-Security": {
        "description": "HTTPS bağlantısını zorunlu kılar.",
        "should_contain": "max-age=",
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "X-Frame-Options": {
        "description": "Clickjacking saldırılarını engeller.",
        "should_contain": "DENY|SAMEORIGIN",
        "recommendation": "X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "description": "MIME tipi sahtekarlığını önler.",
        "should_contain": "nosniff",
        "recommendation": "X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "description": "Yönlendirme bilgilerinin gizliliğini sağlar.",
        "should_contain": "no-referrer",
        "recommendation": "Referrer-Policy: no-referrer"
    },
    "Permissions-Policy": {
        "description": "Tarayıcı API erişimlerini sınırlar.",
        "should_contain": "geolocation",
        "recommendation": "Permissions-Policy: geolocation=(), microphone=()"
    }
}

def run_header_test(url):
    results = []
    results.append("------------------------------------------------------")
    results.append("[=] HTTP Güvenlik Başlıkları (Headers) testi başlatılıyor...")
    results.append("------------------------------------------------------")

    try:
        response = requests.get(url, verify=False, timeout=10)
        headers = response.headers

        results.append(f"[+] {url} adresine bağlantı başarılı.")
        results.append(f"[~] Dönen başlık sayısı: {len(headers)}\n")

        for header, info in SECURITY_HEADERS.items():
            actual_value = headers.get(header)
            if actual_value:
                if info["should_contain"].lower() in actual_value.lower() or \
                   ("|" in info["should_contain"] and any(opt in actual_value.upper() for opt in info["should_contain"].split("|"))):
                    results.append(f"[✓] {header} → Mevcut ✓")
                    results.append(f"    ↳ Değer: {actual_value}")
                    results.append(f"    ↳ Açıklama: {info['description']}")
                else:
                    results.append(f"[⚠] {header} → Mevcut ama yapılandırması önerilen şekilde değil!")
                    results.append(f"    ↳ Mevcut Değer: {actual_value}")
                    results.append(f"    ↳ Önerilen: {info['recommendation']}")
            else:
                results.append(f"[✗] {header} → Eksik!")
                results.append(f"    ↳ Açıklama: {info['description']}")
                results.append(f"    ↳ Eklenmesi önerilir: {info['recommendation']}")
    except Exception as e:
        results.append(f"[X] Header testi sırasında hata oluştu: {e}")

    results.append("------------------------------------------------------")
    results.append("[=] Header testi tamamlandı. Detaylı güvenlik başlıkları kontrolü sonlandı.")
    results.append("------------------------------------------------------")
    return "\n".join(results)

if __name__ == "__main__":
    hedef_url = input("Test edilecek URL: ")
    print(run_header_test(hedef_url))
