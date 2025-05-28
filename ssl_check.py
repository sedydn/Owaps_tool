import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def run_ssl_check(url):
    results = []
    results.append("------------------------------------------------------")
    results.append("[=] SSL Sertifika ve TLS Protokolü Kontrolü Başlatılıyor...")
    results.append("------------------------------------------------------")

    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = 443

        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('organizationName', 'Bilinmiyor')

        subject = dict(x[0] for x in cert['subject'])
        common_name = subject.get('commonName', 'Bilinmiyor')

        valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (valid_to - datetime.utcnow()).days

        # Subject Alternative Names
        san = cert.get('subjectAltName', [])
        san_domains = [entry[1] for entry in san if entry[0].lower() == 'dns']

        results.append(f"[+] TLS Sürümü: {tls_version}")
        results.append(f"[+] Sertifika Sahibi (CN): {common_name}")
        results.append(f"[+] Düzenleyen Kurum: {issued_by}")
        results.append(f"[+] Geçerlilik Başlangıç Tarihi: {valid_from.strftime('%d %B %Y')}")
        results.append(f"[+] Geçerlilik Bitiş Tarihi: {valid_to.strftime('%d %B %Y')}")
        results.append(f"[~] Sertifikanın bitmesine kalan süre: {days_left} gün")

        if san_domains:
            results.append(f"[~] SAN (Alternatif Alan Adları):")
            for d in san_domains:
                results.append(f"    ➤ {d}")
        else:
            results.append("[~] SAN (Alternatif Alan Adları) bulunamadı.")

        if days_left < 0:
            results.append(f"[!] DİKKAT: Sertifika süresi dolmuş!")
        elif days_left < 15:
            results.append(f"[!] Uyarı: Sertifika çok yakında sona erecek!")

        # Güvensiz TLS uyarısı
        if "1.0" in tls_version or "1.1" in tls_version:
            results.append(f"[!] TLS sürümü güncel değil ({tls_version}). TLS 1.2 veya 1.3 önerilir.")

    except Exception as e:
        results.append(f"[X] SSL kontrolü sırasında hata oluştu: {e}")

    results.append("------------------------------------------------------")
    results.append("[=] SSL kontrolü tamamlandı.")
    results.append("------------------------------------------------------")
    return "\n".join(results)

if __name__ == "__main__":
    hedef_url = input("SSL kontrolü yapılacak URL: ")
    print(run_ssl_check(hedef_url))
