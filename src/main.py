import argparse
import sys
from pathlib import Path

# Přidání adresáře 'core' do sys.path pro čisté importy
sys.path.append(str(Path(__file__).resolve().parent / "core"))

from scanner import WifiScanner
from utils import check_dependencies, check_platform


def main():
    parser = argparse.ArgumentParser(description="EtherKit - Network Security Toolkit")
    parser.add_argument(
        "-m", "--monitor",
        type=str,
        required=True,
        help="Network interface (e.g., wlan1)"
    )
    
    args = parser.parse_args()
    
    check_platform()
    check_dependencies()
    
    print("-" * 50)
    print("EtherKit - Network Security Toolkit")
    print("-" * 50)
    
    scanner = WifiScanner(interface=args.monitor)
    
    try:
        # 1. Zapneme monitor mode
        scanner.enable_monitor_mode()
        
        # 2. Provedeme skenování a zobrazení
        scanner.scan_networks()
        scanner.display_networks()
        scanner.export_scan()

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    finally:
        # 3. Vždy bezpečně vrátíme kartu do normálního režimu
        scanner.disable_monitor_mode()


if __name__ == "__main__":
    main()