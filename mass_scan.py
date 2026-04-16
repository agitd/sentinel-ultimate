import asyncio
import os
from core.fuzzer import run_go_fuzzer

TARGETS_FILE = "targets.txt"
MAX_CONCURRENT_SCANS = 4  # Количество одновременных целей

async def scan_worker(queue):
    while True:
        target = await queue.get()
        if target is None:
            break

        # Чистка URL от протоколов для стандартизации
        clean_target = target.replace("https://", "").replace("http://", "").strip()
        url = f"https://{clean_target}"

        print(f"\n" + "!"*40)
        print(f"[+] НАЧИНАЮ СКАН: {url}")
        print("!"*40)

        try:
            # Запуск гибридного фуззера (V13.0)
            await run_go_fuzzer(url, wordlist="fuzz.txt")
        except Exception as e:
            print(f"[-] Ошибка при обработке {url}: {e}")

        queue.task_done()
        print(f"\n[V] ЗАВЕРШЕНО: {url}\n")

async def main():
    if not os.path.exists(TARGETS_FILE):
        print(f"[-] Ошибка: Файл {TARGETS_FILE} не найден!")
        return

    targets = []
    # Читает файл и фильтруем мусор/комментарии
    with open(TARGETS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            # Пропускает пустые строки и строки, начинающиеся с #
            if not line or line.startswith("#"):
                continue

            # Убирает комментарии, которые идут после адреса (например: 1.1.1.1 # сервер)
            target = line.split("#")[0].strip()
            if target:
                targets.append(target)

    if not targets:
        print("[-] Список целей пуст. Нечего сканировать.")
        return

    print(f"[*] Загружено уникальных целей: {len(targets)}")
    print(f"[*] Потоков сканирования: {MAX_CONCURRENT_SCANS}")

    queue = asyncio.Queue()
    for t in targets:
        queue.put_nowait(t)

    # Создание "воркеров", которые будут разгребать очередь
    tasks = []
    for _ in range(MAX_CONCURRENT_SCANS):
        task = asyncio.create_task(scan_worker(queue))
        tasks.append(task)

    # Ждет, пока очередь опустеет
    await queue.join()

    # Останавливает воркеров, отправляя им None
    for _ in range(MAX_CONCURRENT_SCANS):
        queue.put_nowait(None)

    await asyncio.gather(*tasks)
    print("\n" + "="*40)
    print("[+++] МАССОВЫЙ СКАН ПОЛНОСТЬЮ ЗАВЕРШЕН")
    print("="*40)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Скан прерван пользователем.")

