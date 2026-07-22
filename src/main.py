import argparse
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent / "core"))

from core.scanner import WifiScanner
from core.utils import check_dependencies, check_platform


def main():
    parser = argparse.ArgumentParser(description="EtherKit - Network Security Toolkit")
    parser.add_argument(
        "-m", "--monitor",
        type=str,
        required=True,
        help="Network interface in monitor mode (e.g., wlan1)"
    )
    
    args = parser.parse_args()
    
    check_platform()
    check_dependencies()
    
    
    scanner = WifiScanner(interface=args.monitor)
    
    print(f"[*] Initializing scan on interface: {args.monitor}")
    
    try:
        scanner.scan_networks()
        scanner.display_networks()
        scanner.export_scan()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")


if __name__ == "__main__":
    main()