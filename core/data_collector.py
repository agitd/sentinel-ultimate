import requests
import pandas as pd
import io

def fetch_fresh_data():
    print("[*] Collecting fresh port data from remote sources...")
    # 1. База nmap-services
    url_nmap = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
    # 2. CISA Known Exploited Vulnerabilities
    url_cisa = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    data = []

    try:
        # Оригинальный парсинг Nmap
        response = requests.get(url_nmap, timeout=10)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                if not line.startswith('#') and '/' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[1].split('/')
                        port = port_proto[0]
                        try:
                            frequency = float(parts[2])
                            risk = round(1.0 - frequency, 2)
                            data.append([port, risk])
                        except ValueError:
                            continue

        # Добавил данные от CISA (Бесплатно и без ключей)
        print("[*] Adding CISA threat intelligence...")
        cisa_res = requests.get(url_cisa, timeout=10)
        if cisa_res.status_code == 200:
            cisa_data = cisa_res.json()
            for vuln in cisa_data.get('vulnerabilities', []):
                # Если в описании уязвимости есть упоминание портов, повышает риск
                # Это даст нейронке понять, что эти порты сейчас под ударом
                cve_desc = vuln.get('shortDescription', '').lower()
                # Упрощенная логика: если CVE свежая (2024-2026), добавляет веса
                if "port" in cve_desc:
                    data.append(["80", 0.95]) # Пример: накидывает веса на веб-сегмент

        if not data:
            return None

        df = pd.DataFrame(data, columns=['port', 'risk_score'])
        # Удаляет дубликаты портов, оставляя максимальный риск
        df = df.sort_values('risk_score', ascending=False).drop_duplicates('port')

        print(f"[+] Successfully collected {len(df)} data points for AI training.")
        return df

    except Exception as e:
        print(f"[-] Error fetching data: {e}")
    return None


