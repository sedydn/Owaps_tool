import requests
import warnings
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("admin", "123456"),
    ("admin", "1234"),
    ("administrator", "admin"),
]

SUCCESS_KEYWORDS = ["welcome", "dashboard", "logout", "home", "admin panel", "başarı", "hoşgeldiniz"]

def run_auth_bypass_test(url):
    results = []
    results.append("------------------------------------------------------")
    results.append("[=] Authentication Bypass testi başlatılıyor...")
    results.append("------------------------------------------------------")

    try:
        session = requests.Session()
        response = session.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            results.append("[~] Login formu bulunamadı.")
            return "\n".join(results)

        login_form = forms[0]
        action = login_form.get("action", "")
        method = login_form.get("method", "post").lower()

        input_fields = login_form.find_all("input")
        input_names = [inp.get("name", "") for inp in input_fields if inp.get("type") in ["text", "password"]]

        if len(input_names) < 2:
            results.append("[~] Kullanıcı adı ve şifre alanı tespit edilemedi.")
            return "\n".join(results)

        target = urljoin(url, action)
        results.append(f"[+] Login form bulundu. {target} adresine test gönderiliyor...")

        for username, password in COMMON_CREDENTIALS:
            payload = {
                input_names[0]: username,
                input_names[1]: password
            }

            try:
                if method == "post":
                    res = session.post(target, data=payload, verify=False, timeout=10)
                else:
                    res = session.get(target, params=payload, verify=False, timeout=10)

                if any(success in res.text.lower() for success in SUCCESS_KEYWORDS):
                    results.append(f"[!] Başarılı Authentication Bypass tespit edildi!")
                    results.append(f"    ↳ Kullanıcı: {username} | Şifre: {password}")
                    break
                else:
                    results.append(f"[-] Deneme başarısız: {username}:{password}")
            except Exception as ex:
                results.append(f"[X] Hata oluştu: {ex}")
    except Exception as e:
        results.append(f"[X] Form analizinde hata oluştu: {e}")

    results.append("------------------------------------------------------")
    results.append("[=] Authentication Bypass testi tamamlandı.")
    results.append("------------------------------------------------------")
    return "\n".join(results)

if __name__ == "__main__":
    hedef_url = input("Test edilecek login URL: ")
    print(run_auth_bypass_test(hedef_url))
