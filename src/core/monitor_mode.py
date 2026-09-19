import subprocess
from rich.console import Console
from rich.table import Table

class MonitorMode:
    def __init__(self, interface="wlan0"):
        self.interface = interface

    def enable(self):
        try:
            print(f"[green]Turning on monitor mode on interface {self.interface}...[/green]")
            subprocess.run(["systemctl", "stop", "NetworkManager"], check=True)
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["iw", self.interface, "set",  "type", "monitor"], check=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True)
            print(f"[blue]Monitor mode enabled on {self.interface}.[/blue]")
        except subprocess.CalledProcessError as e:
            print(f"[red]Error during subprocess execution: {e} on interface {self.interface}.[/red]")
            print("[red]Make sure the interface is correct and you started the script with root privileges.[/red]")
            return

    def disable(self):
        try:
            print(f"[green]Switching interface {self.interface} back to managed mode...[/green]")
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["iw", self.interface, "set",  "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True)
            subprocess.run(["systemctl", "start", "NetworkManager"], check=True)
            print(f"[blue]Interface {self.interface} successfully reset to managed mode.[/blue]")
        
        except subprocess.CalledProcessError as e:
            print(f"[red]Error during subprocess execution: {e} on interface {self.interface}.[/red]")
            return
