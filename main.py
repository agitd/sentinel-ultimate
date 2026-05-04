import argparse, asyncio, os, logging, sys, re
sys.path.append(os.path.join(os.getcwd(), "venv/lib/python3.13/site-packages"))
from dotenv import load_dotenv
from config.settings import BANNER, HELP_EXAMPLES, AI_ENABLED
from database.manager import ScanDatabase
from core.arp_scanner import scan_network, scan_host
from utils.notifier import send_notification
from utils.reporting import generate_pdf_report, export_to_json, export_to_csv
from core.fuzzer import run_go_fuzzer
from core.fast_ai import get_risk_score
import ai_analyze

# Импортирует pytest для внутренней обработки флага -m
try:
    import pytest
except ImportError:
    pytest = None

logging.basicConfig(level=logging.WARNING)

async def main():
    load_dotenv()
    db = ScanDatabase()

    parser = argparse.ArgumentParser(epilog=HELP_EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)

    # блок аргументов
    parser.add_argument("-n", "--network", required=False)
    parser.add_argument("-f", "--format", choices=['pdf', 'json', 'csv'], help="Export format")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Threads limit")
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--history", action="store_true", help="Show history")
    parser.add_argument("-m", nargs='*', help="Run pytest tests")
    parser.add_argument("-v", action="store_true", help="Verbose mode for pytest")
    parser.add_argument("--fuzz", action="store_true", help="Run Go-fuzzer on detected web services")
    parser.add_argument("--fuzz-ext", default="php,bak,zip,env,sql", help="Extensions for Go-fuzzer")
    parser.add_argument("--fuzz-ignore", default="404,400", help="Statuses to ignore")
    parser.add_argument("--fuzz-vhost", help="VHost header")
    # НОВЫЙ АРГУМЕНТ ДЛЯ АВТООБУЧЕНИЯ
    parser.add_argument("--update-ai", action="store_true", help="Update AI database and retrain model")

    args, unknown = parser.parse_known_args()

    # --- ЭТАП 1: ЛОГИКА ОБНОВЛЕНИЯ AI ---
    if args.update_ai:
        print("[*] Starting Automated AI Update Pipeline...")
        try:
            from core.auto_train import full_auto_update
            full_auto_update()
            print("[+] AI Optimization complete. You can now run scans with the new model.")
        except ImportError:
            print("[-] Error: core/auto_train.py not found. Please create the update scripts first.")
        except Exception as e:
            print(f"[-] Update failed: {e}")
        return

    # 1. Если вызван -m
    if args.m is not None:
        if pytest is None:
            print("[-] Error: pytest not installed. Run: pip install pytest")
            return
        print("[*] Launching internal tests...")
        test_args = args.m if args.m else ['tests/']
        if args.v: test_args.append('-v')
        sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
        pytest.main(test_args)
        return

    # 2. Логика --history
    if args.history:
        try:
            history = db.get_scan_history()
            if history:
                print("\n📜 SCAN HISTORY:")
                print(f"{'ID'.ljust(4)} | {'SUBNET'.ljust(18)} | {'DATE'.ljust(20)} | HOSTS")
                for h in history:
                    print(f"{str(h[0]).ljust(4)} | {h[1].ljust(18)} | {h[2][:19].ljust(20)} | {h[3]}")
            else:
                print("[-] History is empty.")
        except Exception as e:
            print(f"[-] Ошибка при чтении истории: {e}")
        return

    if not args.network:
        print("[-] Error: -n <network> is required. Use -m to run tests or --update-ai to train.")
        return

    # Очистка и баннер
    if os.name == 'nt': os.system('cls')
    else: os.system('clear')
    print(BANNER)

    # Сканирование (Отказоустойчивость)
    try:
        results = await scan_network(args.network)
    except Exception as e:
        print(f"\n[!] Critical Error during scan: {e}")
        logging.error(f"Scan Network Error: {e}", exc_info=True)
        return

    if not results and "/" not in args.network:
        print("[!] No ARP response. Switching to Direct Scan mode...")
        try:
            direct_res = await scan_host(args.network)
            if direct_res:
                results = [direct_res]
        except Exception as e:
            print(f"[-] Direct Scan failed: {e}")

    if results:
        print(f"\n{'IP ADDRESS'.ljust(17)} | {'OS'.ljust(20)} | SERVICES\n" + "-"*90)
        for r in results:
            print(f"{r['ip'].ljust(17)} | {r['os'].ljust(20)} | {r['ports']}")

        # Сохранение с защитой от ошибок БД
        try:
            db.save_scan(args.network, results)
        except Exception as e:
            print(f"[-] Database save error: {e}")

        # Сравнение
        diff = None
        if args.compare:
            try:
                diff = db.compare_scans(args.network)
                if diff:
                    print(f"\n[!] DRIFT: +{len(diff['new'])} New, -{len(diff['gone'])} Gone, *{len(diff['changed'])} Changed")
            except Exception as e:
                print(f"[-] Drift analysis error: {e}")

        # --- AI CONSOLE SUMMARY (Интеллектуальная сортировка) ---
        ai_brief = ""
        if AI_ENABLED:
            print("\n[*] Sentinel AI is thinking...")
            try:
                all_found_ports = []
                for r in results:
                    # Чистка портов от скобок и текста (22(SSH) => 22)
                    clean_ports = re.findall(r'\d+', str(r['ports']))
                    all_found_ports.extend(clean_ports)

                # Нейронка считает риск
                risk_score = get_risk_score(all_found_ports)

                if risk_score >= 0.7:
                    print(f"[!] High Risk detected ({risk_score:.2f}). Consulting Llama 3 for deep analysis...")
                    summary_data = "\n".join([f"Host: {r['ip']}, OS: {r['os']}, Ports: {r['ports']}" for r in results])
                    ai_brief = ai_analyze.ask_ai_analysis(summary_data)
                else:
                    print(f"[-] Low Risk ({risk_score:.2f}). Skip heavy AI analysis.")
                    ai_brief = f"Risk Score: {risk_score:.2f}. No critical threats identified."

                if ai_brief:
                    print(f"\n🤖 AI VERDICT:\n{ai_brief}\n")
            except Exception as e:
                print(f"[-] AI Analysis error: {e}")
        # -------------------------------------------------------------

        # Экспорт
        file_base = f"report_{args.network.replace('/', '_')}"
        try:
            if args.format == 'pdf':
                generate_pdf_report(results, args.network, f"{file_base}.pdf")
                print(f"[+] PDF report saved.")
            elif args.format == 'json':
                export_to_json(results, f"{file_base}.json")
                print(f"[+] JSON report saved.")
            elif args.format == 'csv':
                export_to_csv(results, f"{file_base}.csv")
                print(f"[+] CSV report saved.")
        except Exception as e:
            print(f"[-] Export error: {e}")

        # Уведомления
        if not args.silent:
            try:
                report = f"📡 *Sentinel Report*\nTarget: `{args.network}`\n\n" + "\n".join([r['tg_row'] for r in results])
                if ai_brief:
                    report += f"\n\n🤖 *AI Hint:* {ai_brief[:200]}..."
                send_notification(report, 'telegram')
            except Exception as e:
                print(f"[-] Notifier error: {e}")

        # Запуск Go-фаззера
        if args.fuzz:
            print("\n🚀 Starting Go-fuzzer for web services...")
            for r in results:
                try:
                    if any(web_port in r['ports'] for web_port in ["80", "443", "8080", "HTTPS", "HTTP"]):
                        protocol = "https" if "443" in r['ports'] or "HTTPS" in r['ports'] else "http"
                        target_url = f"{protocol}://{r['ip']}"
                        await run_go_fuzzer(target_url, extensions=args.fuzz_ext, ignore_statuses=args.fuzz_ignore, vhost=args.fuzz_vhost)
                except Exception as e:
                    print(f"[-] Fuzzer error for {r['ip']}: {e}")
    else:
        print("\n[-] No hosts found.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")

