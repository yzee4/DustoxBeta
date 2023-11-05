# Import libraries
import os
import re
import sys
import time
import shutil
import argparse
import threading
import subprocess

# Define colors
class Colors:
    WHITE = '\033[0;97m'
    CYAN = '\033[0;36m'
    LIGHT_RED = '\033[0;91m'
    LIGHT_GREEN = '\033[0;92m'
    YELLOW = '\033[0;93m'
    LIGHT_BLUE = '\033[0;94m'
    PINK = '\033[0;95m'
    NEG_LIGHT_GREEN = '\033[1;92m'
    NEG_LIGHT_RED = '\033[1;91m'
    NEG_YELLOW = '\033[1;93m'
    NEG_PINK = '\033[1;95m'

# Check user mode
def verify_root():
    global root
    if os.geteuid() != 0:
        root = None
    else:
        root = True

# Check required tools
def check_tool_installed(tool_name):
    if tool_name == 'net-tools':
        return os.path.exists('/sbin/ifconfig')
    return shutil.which(tool_name) is not None

def initializing_pupitar_noroot():
    tools_to_check = ['nmap']
    not_installed_tools = [tool for tool in tools_to_check if not check_tool_installed(tool)]
    
    if not_installed_tools:
        for tool in not_installed_tools:
            print(f"{Colors.LIGHT_RED}[-] {Colors.YELLOW}{tool} {Colors.WHITE}not installed. To install, use {Colors.LIGHT_GREEN}'pkg install {tool}'{Colors.WHITE}.")
            sys.exit(0)

# Waiting animation
def waiting_animation(scanning_thread):

    symbols = [".  ", ".. ", "..."]
    while scanning_thread.is_alive():
        for symbol in symbols:
            sys.stdout.write(" " * 12 + "\r")
            sys.stdout.write(f"{Colors.PINK}[/] {Colors.WHITE}Waiting" + symbol)
            sys.stdout.flush()
            time.sleep(0.5)

# Principal scanning logic
def scan_network():
    print(f"{Colors.LIGHT_BLUE}[#] {Colors.WHITE}Scanning started, wait a moment.")

    # -ip flag
    if verbose:
        print(f"\n{Colors.PINK}[/] {Colors.WHITE}Collecting IP information.")
        # Waiting animation
        scanning_thread = threading.current_thread()
        waiting_thread = threading.Thread(target=waiting_animation, args=(scanning_thread,))
        waiting_thread.daemon = True
        waiting_thread.start()

    try:
        # Nmap command
        with open('/dev/null', 'w') as null_file:
            nmap_output = subprocess.check_output(['nmap', '-open', '-T5', *command_list], universal_newlines=True, stderr=null_file)
        paragraphs = re.split(r'\n(?=Nmap scan report)', nmap_output)
        ip_address = None
        num_ips_scanned = 0

        if verbose:
            print()

        # Extracting ip info
        for paragraph in paragraphs:
            match_ip = re.search(r'Nmap scan report for (\S+)(?: \(([\d\.]+)\))?', paragraph)
            match_ports = re.finditer(r'(\d+/[a-zA-Z-0-9]+)\s+(open)\s+([a-zA-Z-0-9]+)', paragraph)
            match_mac = re.search(r'MAC Address: ([0-9A-F:]+) \((.*?)\)', paragraph)
            match_host = re.search(r"Note: Host seems down", paragraph)

            if match_host:
                print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{args.ip}")
                print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No response.")

            if match_ip:
                host_name = match_ip.group(1)
                ip_address = match_ip.group(2) if match_ip.group(2) else None
                if ip_address:
                    print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{ip_address} ({host_name})")
                else:
                    print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{host_name}")

                for match in match_ports:
                    found_port = True

                if match_mac:
                    mac = match_mac.group(1)
                    name = match_mac.group(2)
                    found = True
                else:
                    if not root:
                        mac = f"{Colors.NEG_LIGHT_RED}Need root mode"
                        found = None
                        name = f"{Colors.NEG_LIGHT_RED}Need root mode"
                    if root:
                        mac = f"{Colors.NEG_LIGHT_RED}Not accessible"
                        found = None
                        name = f"{Colors.NEG_LIGHT_RED}Not accessible"

                print(f"""{Colors.YELLOW}NAME: {Colors.WHITE}{name}\n{Colors.YELLOW}MAC:  {Colors.WHITE}{mac}""")

                if found_port:
                    print(f"{Colors.LIGHT_GREEN}PORT         {Colors.LIGHT_GREEN}STATE     {Colors.LIGHT_GREEN}SERVICE")

                    match_ports = re.finditer(r'(\d+/[a-zA-Z-0-9]+)\s+(open)\s+([a-zA-Z-0-9]+)', paragraph)
                    for match in match_ports:
                        port = match.group(1)
                        state = match.group(2)
                        service = match.group(3)

                        chars_to_add = max(0, 9 - len(port))
                        port = port + " " * chars_to_add

                        color_state = (Colors.NEG_LIGHT_GREEN if state == "open"
                                    else Colors.NEG_YELLOW if state == "filtered"
                                    else Colors.NEG_LIGHT_RED)

                        print(f"{Colors.WHITE}{port}    {color_state}{state}      {Colors.WHITE}{service}")
                        
                # Not found open ports
                else:
                    if num_ips_scanned > 0:
                        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No open ports.")
                num_ips_scanned += 1
                
        # Extracting scanning time
        if "Nmap done" in paragraph:
            match_time = re.search(r'in (\d+\.\d+) seconds', paragraph)
            if match_time:
                total_scan_time = match_time.group(1)
                print(f"\n{Colors.LIGHT_GREEN}[+] {Colors.WHITE}{num_ips_scanned} hosts scanned in {total_scan_time} seconds.")

    except subprocess.CalledProcessError as e:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Unknown error: {str(e)}")
    except KeyboardInterrupt:
        if verbose:
            print(f"\n\n{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Scan interrupted")
        else:
            print(f"{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Scan interrupted")
    sys.exit()

# Check valid flags
def is_valid_ip(ip):
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if ip == '0.0.0.0':
        return False
    if re.match(ip_pattern, ip):
        parts = ip.split('.')
        for part in parts:
            if not (0 <= int(part) <= 255):
                return False
        return True
    
def is_valid_port(port):
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return True
    except ValueError:
        return False

def is_valid_rangeip(ip, rangeip):
    try:
        ip_parts = [int(part) for part in ip.split('.')]
        rangeip = int(rangeip)
        if 1 <= rangeip <= 255 and rangeip > ip_parts[-1]:
            return True
    except (ValueError, IndexError):
        return False
    
def is_valid_rangeport(port, rangeport):
    try:
        port = int(port)
        rangeport = int(rangeport)
        return 0 <= port <= 65535 and rangeport >= port
    except ValueError:
        return False

# Flags management
def main():
    global args
    global verbose  
    verbose = None
    global command_list
    command_list = []

    parser = argparse.ArgumentParser(prog = 'dustox', description='Dustox - Network Scanner')
    parser.add_argument('-l', '--localnet', action='store_true', help='Scan the local network')
    parser.add_argument('-gip', '--genericip', action='store_true', help='Scan the local network with generic ip address')
    parser.add_argument('-ip', help='The target IP address')
    parser.add_argument('-rip', '--rangeip', help='The range of IP addresses to scan')
    parser.add_argument('-p', '--port', help='The target port')
    parser.add_argument('-rp', '--rangeport', help='The range of ports to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')

    args = parser.parse_args()

    if not any(vars(args).values()):
        print(f"{interface}")
        sys.exit()

    if not args.ip:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Define ip address.")
        sys.exit()

    if args.rangeip and not args.ip:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}For set range ip, fist specify an IP address with -ip.")
        sys.exit()

    if args.rangeport and not args.port:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}For set range port, fist specify a port value with -p.")
        sys.exit()

    # Variables validation
    if args.ip and not is_valid_ip(args.ip):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid IP format.")
        sys.exit()

    if args.port and not is_valid_port(args.port):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid port format.")
        sys.exit()

    if args.rangeip and not is_valid_rangeip(args.ip, args.rangeip):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range IP format.")
        sys.exit()

    if args.rangeport and not is_valid_rangeport(args.port, args.rangeport):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range port format.")
        sys.exit()

    # Execute with arguments
    if args.ip:
        localnet = None
        genericip = None
        command_list.append(args.ip)

    if args.rangeip:
        command_list.clear()
        command_list.append(f"{args.ip}-{args.rangeip}")
        args.ip = f"{args.ip} ~ {args.rangeip}"

    if args.port:
        if not args.rangeport:
            command_list.append(f'-p {args.port}')

    if args.rangeport:
        command_list.append(f'-p {args.port}-{args.port}')

    if args.verbose:
        verbose = True

    scan_network()

# Interface
def interface_panel():
    global interface
    interface = f"""{Colors.WHITE}Dustox 0.0.1 (BETA)                    {Colors.YELLOW}░▓█▓                         
                                       {Colors.YELLOW}▓████░                        
                                     {Colors.YELLOW}░███▓▓▓                         
                                    {Colors.YELLOW}░███▓░░▓                         
             {Colors.YELLOW}░█████░                ▒██▓▓▓▓░                         
              {Colors.YELLOW}▒▓▓██▒{Colors.YELLOW}█▒     {Colors.PINK}░▓▓▓▓▒▒  {Colors.YELLOW}██▓▓▓▓░                  {Colors.NEG_LIGHT_GREEN}░░▒▒▒▒░ 
               {Colors.YELLOW}░▓▓░▓██▒▒  {Colors.PINK}▒▓▓▓▓▓▓▒▒{Colors.YELLOW}██▓▓▓▓░              {Colors.LIGHT_GREEN}░░▓▓▓▓{Colors.NEG_LIGHT_GREEN}▒▒▒▒▒▒░
                 {Colors.YELLOW}▓▓▓▓▓▓██░{Colors.PINK}▓▓▓▓▓▓▓▓▒{Colors.YELLOW}█▓▓▓▓░           {Colors.LIGHT_GREEN}░░▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}▒▒▒▒▒░
                   {Colors.YELLOW}░▓▓▓▓░{Colors.PINK}▓▓▓▓▓▓▓▓▓▓▒{Colors.YELLOW}▓▓▓▒▒░       {Colors.LIGHT_GREEN}░░▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒▒░
                      {Colors.YELLOW}░▓▒{Colors.PINK}▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒  {Colors.LIGHT_GREEN}░░▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒▒░
                        {Colors.YELLOW}░{Colors.PINK}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒░▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒▒▒▒▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒░░
    ░▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▒░░░░        {Colors.PINK}▓▓▓▓▓▓▓▓▓▓▓▓▓░{Colors.YELLOW}▓▓{Colors.PINK}▒░▒{Colors.LIGHT_GREEN}░▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓░{Colors.NEG_LIGHT_RED}▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓{Colors.NEG_LIGHT_GREEN}░░  ░ 
    ░▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░{Colors.PINK}▓▒▓▓▓▓▓▓▓▓▓▓▒{Colors.YELLOW}▓▓▓{Colors.PINK}░{Colors.YELLOW}▓{Colors.PINK}░▒{Colors.LIGHT_GREEN}▓▓{Colors.NEG_LIGHT_RED}▒▒▒▒▒▒▒▒▒▒{Colors.LIGHT_GREEN}░▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒▒░
    ░▒▒▒▒░{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒░░▒{Colors.LIGHT_GREEN}▓▓▓▓{Colors.YELLOW}███{Colors.PINK}░▓▓▓▓▓▓▓░{Colors.YELLOW}█{Colors.PINK}▒░{Colors.YELLOW}▓▓▓▓{Colors.PINK}▒{Colors.LIGHT_GREEN}░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}▒▒▒▒▒ 
     ▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒▒▒░░░▒▒▒▒░{Colors.YELLOW}█▓{Colors.PINK}░{Colors.YELLOW}█{Colors.PINK}▒▓▓▓▓▓▓░{Colors.YELLOW}▓▓▓{Colors.PINK}░░░▒{Colors.LIGHT_GREEN}░▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒▒░{Colors.LIGHT_GREEN}▒▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒▒░ 
     ░▒▒▒▒░{Colors.LIGHT_GREEN}▓▓{Colors.NEG_LIGHT_RED}░▒▒▒░{Colors.LIGHT_GREEN}▒▒▒{Colors.NEG_LIGHT_RED}▒▒▒░{Colors.LIGHT_GREEN}▓▒▒{Colors.PINK}{Colors.YELLOW}▓█{Colors.PINK}▓▓▓▓▓▓▓░▓▒░░▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}▒▒▒▒▒  
      ░▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓{Colors.NEG_LIGHT_RED}░▒▒▒▒░{Colors.LIGHT_GREEN}▓▓▓▓▓▓{Colors.PINK}▓░░▓▒░░░░▓▓▓▓▓▓░░▒▒{Colors.LIGHT_GREEN}░░░▒▒▓▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒░░  
       ▒▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Colors.PINK}▓▒▓▓▓▓▓▓▓▓▓▓░▓{Colors.NEG_LIGHT_RED}▒▒▒░░{Colors.LIGHT_GREEN}▒▓▓▓▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}░▒░░     
         ░░░░░░▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓{Colors.NEG_LIGHT_RED}░░{Colors.PINK}▓▓▓▓▒▒▓▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒▒░{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒░     
         ░▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒░{Colors.LIGHT_GREEN}▓▓▓▓{Colors.NEG_LIGHT_RED}▒░▒░{Colors.PINK}▓▓▓▓▓▓▓▓▓░▓{Colors.NEG_LIGHT_RED}░░▒░▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}▒▒▒▒░      
          ░▒▒▒▒▒░{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}▒░{Colors.LIGHT_GREEN}▓▓▓{Colors.NEG_LIGHT_RED}▒▒▒░░{Colors.PINK}▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}░▒▒▒{Colors.PINK}▒▒░{Colors.LIGHT_GREEN}▓▓▓░▒▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒▒░       
            ░▒▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▒▒▓▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_RED}░▒▒░{Colors.PINK}▓▓▓▒░░▒▒▒▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}▒  ░▒░         
              ░░▒░  ░▒▒{Colors.LIGHT_GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▒▓▒{Colors.PINK}▓▓▒▒▒▒{Colors.LIGHT_GREEN}▓▓░▓▓▓▓▓{Colors.NEG_LIGHT_GREEN}▒▒▒▒▒░            
                   ▒▒▒▒▒▒▒░░{Colors.LIGHT_GREEN}▓▓▓░▓▓▓▓▓░▓▓{Colors.LIGHT_GREEN}░░░░▓▓{Colors.NEG_LIGHT_GREEN}░▒▒▒▒▒▒▒░              
                     ░░▒▒▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒░    {Colors.NEG_LIGHT_GREEN}░▒▒▒░░                  
                           ░░  ▒▒▒▒▒▒▒▒▒░                                     

{Colors.WHITE}Make sure you are using the latest version at {Colors.LIGHT_GREEN}'https://github/com/yzee4/Dustox'{Colors.WHITE}.

    {Colors.LIGHT_BLUE}-| {Colors.WHITE}coded by Yzee4
    {Colors.LIGHT_BLUE}-| {Colors.WHITE}produced on Python{Colors.WHITE}

{Colors.WHITE}Need help? Use {Colors.LIGHT_GREEN}'-h'{Colors.WHITE}."""

if __name__ == "__main__":
    Colors()
    verify_root()
    initializing_pupitar_noroot()
    interface_panel()
    main()