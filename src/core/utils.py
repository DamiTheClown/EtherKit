import os
import time
import json
import datetime
from pathlib import Path
import sys 
import subprocess

# TODO:
# - jednotný error handler
# - exception management
# - config loader



def clear_terminal():
    if sys.platform.startswith('win'):
        subprocess.run('cls', shell=True)
    else:
        subprocess.run('clear', shell=True)

def timestamp():
    hour = datetime.datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    print(hour)


def create_directory():
    #test file
    file = (Path.cwd() / "logs" / "test.txt")
    json_file = (Path.cwd() / "logs" / "test.json")

    #the / automatically take it as a root directory
    #Path.cwd() gives the current working directory
    directory = (Path.cwd() / "logs").resolve() 
    if directory.exists() and directory.is_dir():
        print("Directory exists")
        if file.exists() and file.is_file():
            print("file exists")
        else:
            print("file doesnt exist, creating file")
            file.touch()
        if json_file.exists() and json_file.is_file():
            print("JSON file exists")
        else:
            print("JSON file doesnt exist, creating file")
            json_file.touch()
    else:
        print("path doesnt exist, creating directory and files")
        directory.mkdir(parents=True, exist_ok=True)
        file.touch()
        json_file.touch()


def save_json(data,path):
    """
    Uložení výsledků
    """


def load_json(path):
    """
    Načtení výsledků
    """


def check_dependencies():
    """
    Kontrola potřebných programů
    """





if __name__ == "__main__":
    # Testování funkcí
    clear_terminal()
    timestamp()
    create_directory()