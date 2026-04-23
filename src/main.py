"""
TEA Forensic Collector - Main Entry Point
Handles privilege check, collection orchestration, and output.
"""

import os
import sys
import json
import time
import ctypes
import datetime
import argparse


def is_admin():
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def elevate():
    """Request UAC elevation and relaunch.
    ShellExecuteW asenkron calisir — yeni elevated process baslamadan
    mevcut process kapanmasin diye kisa sleep eklendi.
    """
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    # ShellExecuteW asenkron calisir. Elevated process'in UAC onayini alip
    # baslamasina yetecek sure beklenir. 5s; yuksek yuklu sistemlerde
    # 2s timeout asimina karsi daha guvenli bir marj saglar.
    time.sleep(5)
    sys.exit(0)


def print_banner():
    banner = (
        "\n"
        "  ████████╗███████╗ █████╗ \n"
        "  ╚══██╔══╝██╔════╝██╔══██╗\n"
        "     ██║   █████╗  ███████║\n"
        "     ██║   ██╔══╝  ██╔══██║\n"
        "     ██║   ███████╗██║  ██║\n"
        "     ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
        "\n"
        "  F O R E N S I C   C O L L E C T O R   v1.2.0\n"
        "  TEA Security -- Windows Artifact Acquisition\n"
        "  ----------------------------------------------\n"
    )
    print(banner)


def print_progress(msg, pct):
    bar_len = 40
    filled = int(bar_len * pct / 100)
    bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
    print(f"\r  [{bar}] {pct:3d}%  {msg:<45}", end="", flush=True)
    if pct >= 98:
        print()


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="TEA Forensic Collector - Windows Artifact Acquisition"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory (default: current directory)"
    )
    parser.add_argument(
        "--no-elevate",
        action="store_true",
        help="Skip UAC elevation attempt"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also save raw JSON output"
    )
    parser.add_argument(
        "--vt-key",
        default=None,
        help="VirusTotal API key (free: https://virustotal.com)"
    )
    parser.add_argument(
        "--yara-rules",
        default=None,
        help="Custom YARA rules directory (default: ./yara_rules)"
    )
    args = parser.parse_args()

    # Privilege check
    if not is_admin():
        print("  [!] Not running as Administrator.")
        if not args.no_elevate:
            print("  [*] Requesting elevation via UAC...")
            try:
                elevate()
            except Exception as e:
                print(f"  [!] Elevation failed: {e}")
                print("  [!] Some artifacts may be incomplete without admin privileges.")
                print("  [*] Continuing with limited privileges...")
        else:
            print("  [!] Continuing without elevation (--no-elevate specified)")
            print("  [!] Some artifacts (Event Logs, Registry, Process hashes) may be incomplete.")
    else:
        print("  [+] Running as Administrator -- full artifact collection enabled.")

    print()

    # Output path
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = os.environ.get("COMPUTERNAME", "unknown")
    base_name = f"tea_forensic_{hostname}_{timestamp}"

    if args.output:
        out_dir = args.output
        os.makedirs(out_dir, exist_ok=True)
    else:
        out_dir = os.getcwd()

    html_path = os.path.join(out_dir, base_name + ".html")
    json_path = os.path.join(out_dir, base_name + ".json")

    print(f"  [*] Output: {html_path}")
    if args.vt_key:
        print(f"  [*] VirusTotal: ENABLED (key: {args.vt_key[:8]}...)")
    else:
        print(f"  [!] VirusTotal: DISABLED (use --vt-key to enable)")
    if args.yara_rules:
        print(f"  [*] YARA rules: {args.yara_rules}")
    print(f"  [*] Starting collection at {datetime.datetime.now().strftime('%H:%M:%S')}")
    print()

    # Import collector
    try:
        from collector import collect_all
    except ImportError:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, script_dir)
        from collector import collect_all

    # Run collection
    # collect_all() her modulu kendi icinde try/except ile korur ve
    # hatalari result[key]={'error':...} olarak yutar. Ancak collect_all()
    # kendisi beklenmedik bir sekilde exception atarsa (ornegin import hatasi,
    # memory error), partial_data ref'i uzerinden o ana kadar toplanan veri
    # kurtarilir. Bu pattern sayesinde emergency JSON her kosulda yazilabilir.
    partial_data = {}

    try:
        data = collect_all(progress_callback=print_progress, partial_ref=partial_data,
                            vt_api_key=args.vt_key, yara_rules_dir=args.yara_rules)
    except Exception as e:
        print(f"\n  [!] Collection error: {e}")
        import traceback
        traceback.print_exc()
        if partial_data:
            print("  [!] Partial data collected -- saving emergency JSON...")
            emergency_path = os.path.join(out_dir, base_name + "_partial.json")
            try:
                with open(emergency_path, 'w', encoding='utf-8') as f:
                    json.dump(partial_data, f, indent=2, ensure_ascii=False,
                              default=lambda x: x.isoformat() if hasattr(x, 'isoformat') else str(x))
                print(f"  [+] Partial data saved: {emergency_path}")
            except Exception as je:
                print(f"  [!] Could not save partial data: {je}")
        else:
            print("  [!] No data collected -- nothing to save.")
        sys.exit(1)

    print(f"\n  [+] Collection complete. Duration: {data['meta'].get('duration_seconds', '?')}s")
    print(f"  [*] Generating HTML report...")

    # Generate HTML report
    try:
        from reporter import generate_html_report
    except ImportError:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, script_dir)
        from reporter import generate_html_report

    generate_html_report(data, html_path)
    print(f"  [+] HTML Report saved: {html_path}")

    # JSON output if requested
    if args.json:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False,
                      default=lambda x: x.isoformat() if hasattr(x, 'isoformat') else str(x))
        print(f"  [+] JSON saved: {json_path}")

    # File size
    html_size = os.path.getsize(html_path) / (1024 * 1024)
    print(f"  [+] Report size: {html_size:.1f} MB")
    print()
    print("  ----------------------------------------------")
    print("  TEA Security -- DFIR Team")
    print("  Open the HTML file in any browser to review.")
    print("  ----------------------------------------------")
    print()

    # Auto-open report
    try:
        os.startfile(html_path)
    except:
        pass

    input("  Press Enter to exit...")


if __name__ == "__main__":
    main()
