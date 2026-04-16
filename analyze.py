import os

def analyze():
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        print("[-] Папка reports не найдена.")
        return

    files = [f for f in os.listdir(reports_dir) if f.endswith(".json")]
    print(f"[*] Анализирую файлов: {len(files)}")
    print("-" * 40)

    found_anything = False

    for file in files:
        file_path = os.path.join(reports_dir, file)
        with open(file_path, "r") as f:
            lines = f.readlines()

            # Ищем строки с "НАЙДЕНО" или кодом 200
            findings = [l.strip() for l in lines if "[+++]" in l or '"status":200' in l]

            if findings:
                found_anything = True
                print(f"\n[!] ЦЕЛЬ: {file.replace('results_', '').replace('.json', '')}")
                print(f"[+] Находок: {len(findings)}")
                # Показываем первые 3 для примера
                for hit in findings[:3]:
                    print(f"    {hit}")

    if not found_anything:
        print("\n[-] Пока ничего интересного не найдено. Продолжай сканить!")

if __name__ == "__main__":
    analyze()

