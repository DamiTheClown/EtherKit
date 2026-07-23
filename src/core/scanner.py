import json
from dataclasses import dataclass, asdict
import subprocess
import sys

from rich.console import Console
from rich.table import Table
from scapy.all import sniff, Dot11, Dot11Elt, RadioTap

@dataclass
class Network:
    ssid: str
    bssid: str
    channel: int
    encryption: str
    signal: int

class WifiScanner:
    def __init__(self, interface: str, timeout: int = 15):
        self.interface = interface
        self.timeout = timeout
        self.networks = {}
        self.console = Console()

    def enable_monitor_mode(self):
        """Enables monitor mod using ip and iw commands."""
        self.console.print(f"[yellow]Enabling monitor mode on {self.interface}...[/yellow]")
        try:
            subprocess.run(["sudo", "pkill", "wpa_supplicant"], stderr=subprocess.DEVNULL)

            subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["sudo", "iw", "dev", self.interface, "set", "type", "monitor"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)

            self.console.print(f"[green]Monitor mode enabled on {self.interface}.[/green]")
        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]Failed to enable monitor mode: {e}[/red]")
            self.console.print("[red]Please ensure you have the necessary permissions and that the interface exists.[/red]")
            sys.exit(1)

    def disable_monitor_mode(self):
        """Disables monitor mode and returns the interface to managed mode."""
        self.console.print(f"[yellow]Disabling monitor mode on {self.interface}...[/yellow]")
        try:
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["sudo", "iw", "dev", self.interface, "set", "type", "managed"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)

            self.console.print(f"[green]Monitor mode disabled on {self.interface}.[/green]")
        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]Failed to disable monitor mode: {e}[/red]")
            sys.exit(1)


    def packet_handler(self, packet):
        if not packet.haslayer(Dot11):
            return
        
        if packet.type == 0 and packet.subtype in [8, 5]:
            bssid = packet[Dot11].addr2

            if not bssid or bssid in self.networks:
                return
            
            ssid = "<hidden>"
            if packet.haslayer(Dot11Elt) and packet.info:
                try:
                    decoded = packet.info.decode("utf-8").strip()
                    if decoded:
                        ssid = decoded
                except UnicodeDecodeError:
                    pass

            channel = 0
            encryption = "OPEN"

            p = packet[Dot11Elt]
            while isinstance(p, Dot11Elt):
                if p.ID == 3:
                    try:
                        channel = int(p.info[0])
                    except (TypeError, IndexError):
                        pass
                elif p.ID == 48:
                    encryption = "WPA2"
                elif p.ID == 221 and p.info.startswith(b"\x00P\xf2\x01\x01\x00"):
                    if encryption == "OPEN":
                        encryption = "WPA"
                p = p.payload

            if encryption == "OPEN" and packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").find("privacy") > 0:
                encryption = "WEP"

            signal = -100
            if packet.haslayer(RadioTap) and hasattr(packet[RadioTap], "dBm_AntSignal"):
                signal = int(packet[RadioTap].dBm_AntSignal)

            self.networks[bssid] = Network(
                ssid=ssid,
                bssid=bssid,
                channel=channel,
                encryption=encryption,
                signal=signal
            )

    def scan_networks(self):
        """Pure network scanning logic."""
        self.networks.clear()
        
        with self.console.status(f"[bold green]Scanning on {self.interface} for {self.timeout}s...", spinner="dots"):
            sniff(iface=self.interface, prn=self.packet_handler, timeout=self.timeout, store=False)

        sorted_networks = sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)
        return sorted_networks

    def display_networks(self):
        sorted_networks = sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)

        if not sorted_networks:
            self.console.print(f"[red]No networks found on {self.interface}.[/red]")
            return

        table = Table(title="WiFi Scan Results")
        table.add_column("ID", justify="right", style="cyan", no_wrap=True)
        table.add_column("SSID", style="magenta")
        table.add_column("BSSID", style="green")
        table.add_column("CH", justify="right")
        table.add_column("ENC", justify="left")
        table.add_column("PWR", justify="right")

        for idx, network in enumerate(sorted_networks, start=1):
            table.add_row(
                str(idx),
                network.ssid,
                network.bssid,
                str(network.channel),
                network.encryption,
                f"{network.signal} dBm"
            )

        self.console.print(table)

    def export_scan(self, filename="scan_results.json"):
        if not self.networks:
            return

        sorted_networks = sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)
        with open(filename, "w") as f:
            json.dump([asdict(net) for net in sorted_networks], f, indent=4)