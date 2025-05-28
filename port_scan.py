import socket
from concurrent.futures import ThreadPoolExecutor

# Yaygın bazı portların bilinen isimleri
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
}

def scan_port(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                sock.settimeout(1)
                banner = sock.recv(1024).decode(errors='ignore').strip()
            except:
                banner = "Banner alınamadı"
            service = COMMON_PORTS.get(port, "Bilinmeyen Servis")
            return f"[+] {port} (Açık) → {service} | Banner: {banner}"
    except:
        return None  # Kapalı portları loglama

def run_port_scan(host):
    results = []
    results.append("------------------------------------------------------")
    results.append("[=] Tüm portlar (1–65535) taranıyor...")
    results.append("------------------------------------------------------")

    open_ports = []

    with ThreadPoolExecutor(max_workers=500) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in range(1, 15536)}
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
                open_ports.append(futures[future])

    results.append("------------------------------------------------------")
    if open_ports:
        results.append(f"[+] Toplam {len(open_ports)} açık port bulundu.")
    else:
        results.append("[!] Açık port bulunamadı.")
    results.append("[=] Geniş port taraması tamamlandı. Bir sonraki zafiyet taramasına geçiliyor...")
    results.append("------------------------------------------------------")

    return "\n".join(results)

if __name__ == "__main__":
    hedef = input("Hedef IP veya domain girin: ")
    print(run_port_scan(hedef))
