import asyncio
import os
import json
import logging

logger = logging.getLogger(__name__)

# +++ ИСПРАВЛЕНО: Добавлены новые аргументы в сигнатуру функции +++
async def run_go_fuzzer(target_url: str, wordlist: str = "fuzz.txt", extensions: str = None, ignore_statuses: str = None, vhost: str = None):
    """
    Sentinel V13.0: Исправлены права доступа, пути и добавлен Fallback сохранения.
    Поддерживает расширения, кастомные статусы и VHost.
    """
    current_file_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_dir = os.path.abspath(os.path.join(current_file_dir, "..", "fuzzer-engine"))
    reports_dir = os.path.abspath(os.path.join(current_file_dir, "..", "reports"))

    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)

    # ПРИНУДИТЕЛЬНЫЙ FIX ПРАВ: чтобы Docker точно мог писать
    os.system(f"chmod 777 {reports_dir}")

    # Уникальное имя файла
    clean_host = target_url.replace("https://", "").replace("http://", "").rstrip('/').replace(".", "_").replace("/", "_")
    report_file = f"results_{clean_host}.json"
    report_path_host = os.path.join(reports_dir, report_file)

    target_url = target_url.rstrip('/')

    # КОМАНДА DOCKER
    command = [
        "docker", "run", "--rm", "-i",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{wordlist_dir}:/app/wordlists",
        "-v", f"{reports_dir}:/app/reports",
        "sentinel-fuzzer",
        "-u", target_url,
        "-w", f"/app/wordlists/{wordlist}",
        "-o", f"/app/reports/{report_file}",
        "-t", "100"
    ]

    # +++ ДОБАВЛЕНО: Динамическое добавление новых флагов, если они переданы +++
    if extensions:
        command.extend(["-x", extensions])
    if ignore_statuses:
        command.extend(["-is", ignore_statuses])
    if vhost:
        command.extend(["-H", vhost])

    print(f"\n" + "="*50)
    print(f"[*] SENTINEL ENGINE START")
    print(f"[*] Target: {target_url}")
    if extensions: print(f"[*] Extensions: {extensions}")
    if vhost: print(f"[*] VHost: {vhost}")
    print(f"[*] Report: reports/{report_file}")
    print("="*50 + "\n")

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        output_list = []
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            line_decoded = line.decode().strip()
            print(line_decoded) # Вывод в консоль
            output_list.append(line_decoded) # Сохраняем в память

        await process.wait()

        print("\n" + "-" * 50)
        if process.returncode == 0:
            print(f"[+] Scan finished successfully.")

            if os.path.exists(report_path_host) and os.path.getsize(report_path_host) > 0:
                print(f"🔥 Отчет сохранен движком: {report_path_host}")
            else:
                print(f"[*] Fallback: Сохраняю вывод через Python...")
                with open(report_path_host, "w") as f:
                    f.write("\n".join(output_list))
                print(f"🔥 Отчет принудительно сохранен: {report_path_host}")
        else:
            _, stderr = await process.communicate()
            print(f"[-] Engine error: {stderr.decode()}")

    except Exception as e:
        print(f"[-] Execution error: {e}")

