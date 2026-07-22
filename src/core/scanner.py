import json
from dataclasses import dataclass, asdict

from rich.console import Console
from rich.table import Table
from scapy.all import sniff, Dot11, Dot11Elt, RadioTap

# from core.utils import some_utility_function

# TODO:
# - vytvořit datový model Network
# - přidat filtrování
# - přidat řazení podle signálu
# - přidat export JSON


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
        self.networks = []


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

                if encryption == "OPEN" and packet.startswith("{Dot11Beacon:%Dot11Beacon.cap%}").find("privacy") > 0:
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
                    self.networks.clear()
        
                    with self.console.status(f"[bold green]Scanning on {self.interface} for {self.timeout}s...", spinner="dots"):
                         sniff(iface=self.interface, prn=self.packet_handler, timeout=self.timeout, store=False)

                    sorted_networks = sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)
                    return sorted_networks

                def display_networks(self):
                    sorted_networks = sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)

                    if not sorted_networks:
                        self.console.print(f"[red]No networks found on {self.interface}. Make sure the interface is in monitor mode.[/red]")
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
                            str(network.signal)
                        )

                    self.console.print(table)

                def export_scan(self, filename="scan_results.json"):
                    if not self.networks:
                        return

                    sorted_networks = sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)
                    with open(filename, "w") as f:
                        json.dump([asdict(net) for net in sorted_networks], f, indent=4)