import argparse, asyncio, os, logging, sys
from dotenv import load_dotenv
from config.settings import BANNER, HELP_EXAMPLES
from database.manager import ScanDatabase
from core.arp_scanner import scan_network
from utils.notifier import send_notification
from utils.reporting import generate_pdf_report, export_to_json, export_to_csv

# Импорт pytest для внутренней обработки флага -m
try:
    import pytest
except ImportError:
    pytest = None

logging.basicConfig(level=logging.WARNING)

async def main():
    load_dotenv()
    db = ScanDatabase()

    parser = argparse.ArgumentParser(epilog=HELP_EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)

    # Флаги
    parser.add_argument("-n", "--network", required=False)
    parser.add_argument("-f", "--format", choices=['pdf', 'json', 'csv'], help="Export format")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Threads limit")
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--history", action="store_true", help="Show history")

    # ЛОГИКА ДЛЯ ТВОЕГО ЗАПРОСА: добавляем поддержку -m и сбор всех аргументов после него
    parser.add_argument("-m", nargs='*', help="Run pytest tests")
    parser.add_argument("-v", action="store_true", help="Verbose mode for pytest")

    args, unknown = parser.parse_known_args()

    # 1. Если вызван -m (запуск тестов прямо из мейна)
    if args.m is not None:
        if pytest is None:
            print("[-] Error: pytest not installed. Run: pip install pytest")
            return
        print("[*] Launching internal tests...")
        # Собрал аргументы: если после -m что-то есть (типа pytest tests/ -v), берёт их
        test_args = args.m if args.m else ['tests/']
        if args.v: test_args.append('-v')

        # Фикс путей для импортов внутри тестов
        sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
        pytest.main(test_args)
        return

    # 2. Логика --history
    if args.history:
        history = db.get_scan_history()
        if history:
            print("\n📜 SCAN HISTORY:")
            print(f"{'ID'.ljust(4)} | {'SUBNET'.ljust(18)} | {'DATE'.ljust(20)} | HOSTS")
            for h in history:
                print(f"{str(h[0]).ljust(4)} | {h[1].ljust(18)} | {h[2][:19].ljust(20)} | {h[3]}")
        else:
            print("[-] History is empty.")
        return

    if not args.network:
        print("[-] Error: -n <network> is required. Use -m to run tests.")
        return

    # Очистка и баннер
    if os.name == 'nt': os.system('cls')
    else: os.system('clear')
    print(BANNER)

    # Сканирование
    results = await scan_network(args.network)

    if results:
        print(f"\n{'IP ADDRESS'.ljust(17)} | {'OS'.ljust(20)} | SERVICES\n" + "-"*90)
        for r in results:
            print(f"{r['ip'].ljust(17)} | {r['os'].ljust(20)} | {r['ports']}")

        db.save_scan(args.network, results)

        # Сравнение
        diff = None
        if args.compare:
            diff = db.compare_scans(args.network)
            if diff:
                print(f"\n[!] DRIFT: +{len(diff['new'])} New, -{len(diff['gone'])} Gone, *{len(diff['changed'])} Changed")

        # Экспорт
        file_base = f"report_{args.network.replace('/', '_')}"
        if args.format == 'pdf':
            generate_pdf_report(results, args.network, f"{file_base}.pdf")
            print(f"[+] PDF report saved.")
        elif args.format == 'json':
            export_to_json(results, f"{file_base}.json")
            print(f"[+] JSON report saved.")
        elif args.format == 'csv':
            export_to_csv(results, f"{file_base}.csv")
            print(f"[+] CSV report saved.")

        # Уведомления
        if not args.silent:
            report = f"📡 *Sentinel Report*\nTarget: `{args.network}`\n\n" + "\n".join([r['tg_row'] for r in results])
            if diff and (diff['new'] or diff['changed']):
                report += "\n\n⚠️ *Network changes detected!*"
            send_notification(report, 'telegram')
    else:
        print("\n[-] No hosts found. Use sudo for ARP scan.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

