import json
from dataclasses import dataclass

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
            
