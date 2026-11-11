import argparse
import sys
from pathlib import Path
 
# Add the 'core' directory to sys.path to allow imports from it
sys.path.append(str(Path(__file__).resolve().parent / "core"))
 
from core.scanner import WifiScanner
from core.utils import check_dependencies, check_platform
 
 
def parse_args():
    """Parses command-line arguments, e.g., `-m wlan0`."""
    parser = argparse.ArgumentParser(description="EtherKit - Network Security Toolkit | Made by: DamiTheClown && ArmycekCZ")
    parser.add_argument(
        "-m", "--monitor",
        type=str,
        required=True,
        help="Network interface to use for monitoring (e.g., wlan0)"
    )
    return parser.parse_args()
 
 
def main():
    args = parse_args()
 
    # Check if platform is linux and if all directories and files exist, and if all dependencies are installed.
    check_platform()
    check_dependencies()
 
    print("-" * 50)
    print("EtherKit - Network Security Toolkit")
    print("-" * 50)
 
    scanner = WifiScanner(interface=args.monitor)
 
    try:
        # 1. Enable monitor mode on the specified interface
        scanner.enable_monitor_mode()
 
        # 2. Start scanning for networks and display results
        scanner.scan_networks()
        scanner.display_networks()
        scanner.export_scan()
 
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    finally:
        # 3. This block ALWAYS runs - whether the scan finished successfully,
        # crashed with an error, or you stopped it using Ctrl+C.
        # This prevents the card from getting stuck in monitor mode..
        scanner.disable_monitor_mode()
 
 
if __name__ == "__main__":
    main()