import argparse
from core.scanner import WifiScanner
from core.utils import *


# TODO:
# - vytvořit CLI argumenty
# - přidat --interface
# - přidat --scan
# - přidat --report
# - přidat verbose mód


def banner():
    """
    ASCII logo EtherKit
    """

def parse_arguments():
    """
    CLI argumenty
    """

def main_menu():
    """
    Hlavní menu programu
    """

def load_modules():
    """
    Načte dostupné moduly
    """



import argparse

# 1. Vytvoření parseru
parser = argparse.ArgumentParser(description="Můj skript")

# 2. Přidání parametru
parser.add_argument("jmeno", help="Zadej své jméno")

# 3. Zpracování a vypsání
args = parser.parse_args()
print(f"Ahoj, {args.jmeno}!")