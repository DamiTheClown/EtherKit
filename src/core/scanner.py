"""
scanner.py
-----------
WiFi scanning tool using Scapy to capture Beacon and Probe Response frames
in monitor mode.
"""

import json
from dataclasses import dataclass, asdict
import subprocess
import sys

from rich.console import Console
from rich.table import Table
from scapy.all import sniff, Dot11, Dot11Elt, Dot11Beacon, Dot11ProbeResp, RadioTap


@dataclass
class Network:
    """Stores information about a discovered WiFi network."""
    ssid: str          # Network name (SSID)
    bssid: str         # AP MAC address
    channel: int        # Channel number (1-13)
    encryption: str     # OPEN / WEP / WPA / WPA2
    signal: int          # Signal strength in dBm


class WifiScanner:
    """Handles network scanning and interface modes."""

    def __init__(self, interface: str, timeout: int = 15):
        self.interface = interface   # e.g. wlan0
        self.timeout = timeout       # scan duration in seconds
        self.networks = {}           # BSSID -> Network mapping
        self.console = Console()

    # ------------------------------------------------------------------
    # Interface control
    # ------------------------------------------------------------------

    def enable_monitor_mode(self):
        """
        Enables monitor mode on the network interface.
        
        Stops wpa_supplicant to prevent interface conflicts.
        """
        self.console.print(f"[yellow]Enabling monitor mode on {self.interface}...[/yellow]")
        try:
            # kill wpa_supplicant to prevent interference
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
        """Restores the interface to managed mode."""
        self.console.print(f"[yellow]Disabling monitor mode on {self.interface}...[/yellow]")
        try:
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["sudo", "iw", "dev", self.interface, "set", "type", "managed"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)

            self.console.print(f"[green]Monitor mode disabled on {self.interface}.[/green]")
        except subprocess.CalledProcessError as e:
            self.console.print(f"[red]Failed to disable monitor mode: {e}[/red]")
            sys.exit(1)

    # ------------------------------------------------------------------
    # Packet parsing
    # ------------------------------------------------------------------

    def packet_handler(self, packet):
        """Processes captured packets and filters 802.11 management frames."""
        # ignore non-WiFi frames
        if not packet.haslayer(Dot11):
            return

        # check for Beacon (subtype 8) or Probe Response (subtype 5)
        is_beacon_or_probe_response = packet.type == 0 and packet.subtype in (8, 5)
        if not is_beacon_or_probe_response:
            return

        # addr2 contains the AP BSSID
        bssid = packet[Dot11].addr2
        if not bssid or bssid in self.networks:
            # skip invalid or already processed BSSIDs
            return

        ssid = self._extract_ssid(packet)
        channel, encryption = self._extract_channel_and_encryption(packet)
        signal = self._extract_signal(packet)

        self.networks[bssid] = Network(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            encryption=encryption,
            signal=signal,
        )

    def _extract_ssid(self, packet):
        """Extracts the SSID from Information Elements."""
        if not packet.haslayer(Dot11Elt):
            return "<unknown>"

        raw_ssid = packet[Dot11Elt].info
        if not raw_ssid:
            return "<hidden>"

        try:
            return raw_ssid.decode("utf-8").strip() or "<hidden>"
        except UnicodeDecodeError:
            # corrupted SSID data
            return "<invalid>"

    def _extract_channel_and_encryption(self, packet):
        """Parses Information Elements to find channel and encryption type."""
        channel = 0
        encryption = "OPEN"

        element = packet[Dot11Elt]
        # iterate through Information Elements
        while isinstance(element, Dot11Elt):
            if element.ID == 3:
                # DS Parameter Set (channel info)
                try:
                    channel = int(element.info[0])
                except (TypeError, IndexError):
                    pass

            elif element.ID == 48:
                # RSN Element (WPA2/WPA3)
                encryption = "WPA2"

            elif element.ID == 221 and element.info.startswith(b"\x00P\xf2\x01\x01\x00"):
                # Vendor-specific OUI for WPA
                if encryption == "OPEN":
                    encryption = "WPA"

            element = element.payload

        if encryption == "OPEN" and self._has_privacy_bit(packet):
            # fallback to WEP if privacy bit is set without WPA/WPA2 tags
            encryption = "WEP"

        return channel, encryption

    def _has_privacy_bit(self, packet):
        """Checks if the privacy bit is set in capability flags."""
        if packet.haslayer(Dot11Beacon):
            capability = packet[Dot11Beacon].sprintf("%Dot11Beacon.cap%")
        elif packet.haslayer(Dot11ProbeResp):
            capability = packet[Dot11ProbeResp].sprintf("%Dot11ProbeResp.cap%")
        else:
            return False

        return "privacy" in capability

    def _extract_signal(self, packet):
        """Extracts signal strength (dBm) from RadioTap header."""
        if packet.haslayer(RadioTap):
            signal = getattr(packet[RadioTap], "dBm_AntSignal", None)
            if signal is not None:
                return int(signal)
        return -100  # default value when signal is missing

    # ------------------------------------------------------------------
    # Output and export
    # ------------------------------------------------------------------

    def scan_networks(self):
        """Runs packet sniffing for specified timeout."""
        self.networks.clear()

        with self.console.status(f"[bold green]Scanning on {self.interface} for {self.timeout}s...", spinner="dots"):
            # store=False keeps memory usage low
            sniff(iface=self.interface, prn=self.packet_handler, timeout=self.timeout, store=False)

        return self._sorted_networks()

    def display_networks(self):
        """Displays results in a formatted table."""
        sorted_networks = self._sorted_networks()

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
                f"{network.signal} dBm",
            )

        self.console.print(table)

    def export_scan(self, filename="scan_results.json"):
        """Saves results to a JSON file."""
        if not self.networks:
            return

        sorted_networks = self._sorted_networks()
        with open(filename, "w") as f:
            json.dump([asdict(net) for net in sorted_networks], f, indent=4)

    def _sorted_networks(self):
        """Sorts networks by signal strength (strongest first)."""
        return sorted(self.networks.values(), key=lambda net: net.signal, reverse=True)