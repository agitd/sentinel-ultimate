import asyncio
import subprocess
import os
import json
import logging

logger = logging.getLogger(__name__)

async def run_go_fuzzer(target_url: str, wordlist: str = "list.txt"):
    """
    Запуск Go-фаззера внутри Docker контейнера.
    Интеграция с Sentinel v11.0
    """
    current_dir = os.getcwd()
    report_path = "reports/results.json" # Путь к файлу, который создает Go-движок

    if not os.path.exists("reports"):
        os.makedirs("reports")

    command = [
        "docker", "run", "--rm",
        "-v", f"{current_dir}:/root/",
        "sentinel-fuzzer",
        "-u", target_url,
        "-w", wordlist,
        "-t", "50"
        # Убрал -v, чтобы не забивать консоль лишним мусором, оставил только хиты
    ]

    print(f"[*] Launching Go-engine for: {target_url}")

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            print(f"[+] Fuzzing completed for {target_url}")

            # --- ЛОГИКА ДЛЯ ЗАПРОСА: Чтение и вывод результатов ---
            if os.path.exists(report_path):
                try:
                    with open(report_path, "r") as f:
                        results = json.load(f)
                        if results:
                            print(f"\n🔥 FOUND ON {target_url}:")
                            for res in results:
                                # Выводит статус и путь (например: [200] /admin)
                                print(f"  [{res.get('status')}] {res.get('url')}")
                        else:
                            print(f"[-] No paths found on {target_url}")
                except Exception as e:
                    print(f"[-] Error reading reports: {e}")
            # -----------------------------------------------------------

        else:
            error_msg = stderr.decode()
            if "Permission denied" in error_msg:
                print(f"[-] Docker Error: Permission denied.")
            else:
                logger.error(f"Fuzzer error: {error_msg}")

    except Exception as e:
        print(f"[-] Failed to run Docker: {e}")

