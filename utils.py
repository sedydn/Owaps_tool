import os
import json
from urllib.parse import urlparse

URL_HISTORY_FILE = "url_history.json"

def validate_url(url):
    if url.startswith("http://") or url.startswith("https://"):
        parsed = urlparse(url)
        return bool(parsed.netloc)
    return False

def load_url_history():
    if os.path.exists(URL_HISTORY_FILE):
        try:
            with open(URL_HISTORY_FILE, 'r', encoding='utf-8') as file:
                return json.load(file)
        except Exception as e:
            print(f"[X] URL geçmişi okunamadı: {e}")
            return []
    return []

def save_url_to_history(url):
    history = load_url_history()
    if url not in history:
        history.append(url)
        try:
            with open(URL_HISTORY_FILE, 'w', encoding='utf-8') as file:
                json.dump(history, file, indent=4)
        except Exception as e:
            print(f"[X] URL geçmişine yazılamadı: {e}")

if __name__ == "__main__":
    test_url = "https://www.example.com"
    if validate_url(test_url):
        print("URL geçerli. Kaydediliyor...")
        save_url_to_history(test_url)
        print("URL geçmişi:", load_url_history())
    else:
        print("URL geçersiz.")