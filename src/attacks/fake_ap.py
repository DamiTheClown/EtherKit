import time
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp, RandMac
import sys, subprocess

# TODO:
# - stav modulu
# - logování
# - cleanup po ukončení

# airmon-ng check kill

# airmon-ng start wlan0
# airmon-ng stop wlan0
#sudo systemctl start NetworkManager

class FakeAPModule:
    def __init__(self):
        self.state = "STOPPED"
        self.ap_ssid = {}
        self.interface = "wlan0"
        self.ap_macs = {}

    def configure(self, networks_dict, interface="wlan0"):
        self.ap_ssid = networks_dict
        self.interface = interface
        self.ap_macs = {ssid: str(RandMac()) for ssid in networks_dict}

    def start(self):
        self.state = "RUNNING"

        try:
            print(f"Turning on monitor mode on interface {self.interface}...")
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["iw", self.interface, "set",  "type", "monitor"], check=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True)
            print(f"Monitor mode enabled on {self.interface}.")

        except subprocess.CalledProcessError as e:
            print(f"Error during subprocess execution: {e} on interface {self.interface}.")
            print("Make sure the interface is correct and you started the script with root privileges.")
            return

        try:
            while self.state == "RUNNING":
                for ssid, password in self.ap_ssid.items():
                    if password is None:
                        mac_address = self.ap_macs[ssid]

                        packet = (RadioTap() / 
                                Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac_address, addr3=mac_address) / 
                                Dot11Beacon(cap="ESS") / 
                                Dot11Elt(ID="SSID", info=ssid) /
                                Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")/
                                Dot11Elt(ID="DSset", info=b"\x06"))
                        
                        sendp(packet, iface=self.interface, count=1, verbose=False)

                time.sleep(0.1)

        except KeyboardInterrupt:
            print("\n[!] Turning off fake APs...")
            self.stop()

    def stop(self):
        if self.state == "STOPPED":
            print("Modul is already stopped.")
            return
        self.state = "STOPPED"

        try:
            print(f"Switching interface {self.interface} back to managed mode...")
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["iw", self.interface, "set",  "type", "managed"], check=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True)
            print(f"Interface {self.interface} successfully reset to managed mode.")

        except subprocess.CalledProcessError as e:
            print(f"Error during subprocess execution: {e} on interface {self.interface}.")
            return




    def status(self):
        ...


if __name__ == "__main__":
    fake_ap = FakeAPModule()
    fake_ap.configure({"FakeNetwork1": None, "FakeNetwork2": None, "SkibidyRizzler": None}, interface="wlan0")
    fake_ap.start()