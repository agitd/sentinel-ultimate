import requests
import pandas as pd
import io

def fetch_fresh_data():
    print("[*] Collecting fresh port data from remote sources...")
    #  база nmap-services (там тысячи портов и их популярность)
    url = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Парсинг текстового файла nmap (пропуск комментариев)
            data = []
            for line in response.text.split('\n'):
                if not line.startswith('#') and '/' in line:
                    parts = line.split()
                    port_proto = parts[1].split('/')
                    port = port_proto[0]
                    # Назначение риска на основе частоты (простой пример логики)
                    frequency = float(parts[2])
                    # Чем реже и страннее порт, тем выше подозрение (или наоборот, по вроде, логике)
                    risk = round(1.0 - frequency, 2)
                    data.append([port, risk])

            df = pd.DataFrame(data, columns=['port', 'risk_score'])
            return df
    except Exception as e:
        print(f"[-] Error fetching data: {e}")
    return None

