# Dustox by Yzee4
#
# MIT License
#
# Copyright (c) 2023 Yzee4
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Import libraries
import os
import re
import sys
import time
import signal
import shutil
import argparse
import threading
import subprocess

# Define colors
class Colors:
    WHITE = '\033[0;97m'
    LIGHT_RED = '\033[0;91m'
    LIGHT_GREEN = '\033[0;92m'
    LIGHT_BLUE = '\033[0;94m'
    YELLOW = '\033[0;93m'
    PINK = '\033[0;95m'
    CYAN = '\033[0;96m'

# Check user mode
def verify_root():
    global root
    if os.geteuid() != 0:
        root = None
    else:
        root = True

# Check required tools
def check_tool_installed(tool_name):
    return shutil.which(tool_name) is not None

def initializing_dustox():
    tools_to_check = ['nmap', 'ip']
    not_installed_tools = [tool for tool in tools_to_check if not check_tool_installed(tool)]
    
    if not_installed_tools:
        for tool in not_installed_tools:
            print(f"{Colors.LIGHT_RED}[-] {Colors.YELLOW}{tool} {Colors.WHITE}not installed. To install, use {Colors.LIGHT_GREEN}'pkg install {tool}'{Colors.WHITE}")
            sys.exit(0)

# Waiting animation
stop_animation = False
def waiting_animation(scanning_thread):
    global stop_animation
    while not stop_animation:
        symbols = [".  ", ".. ", "..."]
        while scanning_thread.is_alive():
            for symbol in symbols:
                print(" " * 12 + f"\r{Colors.PINK}[/] {Colors.WHITE}Waiting{symbol}", end='', flush=True)
                time.sleep(0.5)

# Principal scanning logic
def scan_network():
    print(f"{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Scanning started\n")

    # --localnet flag
    if localnet:
        result = subprocess.run("ip route | grep -oP 'src \K\S+' | head -n 1", shell=True, capture_output=True, text=True)
        local_ips = result.stdout.splitlines()
        if len(local_ips) == 0:
            print('')
            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Failed to scan local network ip")
            sys.exit(0)
        local_ips_with_subnet = [ip + "/24" for ip in local_ips]
        command_list.append(*local_ips_with_subnet)

    # -ip flag
    # Waiting animation
    scanning_thread = threading.current_thread()
    waiting_thread = threading.Thread(target=waiting_animation, args=(scanning_thread,))
    waiting_thread.daemon = True
    waiting_thread.start()

    if timescan != None:
        def timer_to_scan(signum, frame):
            global stop_animation
            stop_animation = True
            time.sleep(2.5)
            print(f"\n\n{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Time is over\n\n{Colors.WHITE}Copyright (c) 2023 Yzee4")
            sys.exit()
        signal.signal(signal.SIGALRM, timer_to_scan)
        signal.alarm(timescan) 

    try:
        repeatcounter = 1
        for _ in range(repeat):
            # Nmap command
            with open('/dev/null', 'w') as null_file:
                nmap_output = subprocess.check_output(['nmap', '-open', '-T5', *command_list], universal_newlines=True, stderr=null_file)
            paragraphs = re.split(r'\n(?=Nmap scan report)', nmap_output)
            ip_address = None
            num_ips_scanned = 0

            print()

            # Extracting ip info
            for paragraph in paragraphs:
                match_ip = re.search(r'Nmap scan report for (\S+)(?: \(([\d\.]+)\))?', paragraph)
                match_ports = re.finditer(r'(\d+/[a-zA-Z-0-9]+)\s+(open)\s+([a-zA-Z-0-9]+)', paragraph)
                match_mac = re.search(r'MAC Address: ([0-9A-F:]+) \((.*?)\)', paragraph)
                match_host = re.search(r"Note: Host seems down", paragraph)

                if match_host:
                    print(f"\n{Colors.LIGHT_GREEN}----| IP: {Colors.WHITE}{args.ip}")
                    print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No response")

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
                    else:
                        if not root:
                            mac = f"{Colors.LIGHT_RED}Need root mode"
                            name = f"{Colors.LIGHT_RED}Need root mode"
                        if root:
                            mac = f"{Colors.LIGHT_RED}Not accessible"
                            name = f"{Colors.LIGHT_RED}Not accessible"

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

                            color_state = (Colors.LIGHT_GREEN if state == "open"
                                        else Colors.YELLOW if state == "filtered"
                                        else Colors.LIGHT_RED)

                            print(f"{Colors.WHITE}{port}    {color_state}{state}      {Colors.WHITE}{service}")
                            
                    # Not found open ports
                    else:
                        if num_ips_scanned > 0:
                            print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}No open ports")
                    num_ips_scanned += 1
                    
            # Extracting scanning time
            if "Nmap done" in paragraph:
                match_time = re.search(r'in (\d+\.\d+) seconds', paragraph)
                if match_time:
                    total_scan_time = match_time.group(1)
                    if num_ips_scanned == 0:
                        print(f"\n{Colors.LIGHT_RED}[-] {Colors.WHITE}No results for the search. Try again or change some options")
                        sys.exit(0)
                    print(f"\n{Colors.LIGHT_GREEN}[+] {Colors.WHITE}{num_ips_scanned} hosts scanned in {total_scan_time} seconds\n")
                    if repeat > 1:
                        if repeat == repeatcounter:
                            print(f"{Colors.CYAN}[>] {Colors.WHITE}Repeat counter {Colors.LIGHT_GREEN}({repeatcounter}/{repeat})\n")
                        else:
                            print(f"{Colors.CYAN}[>] {Colors.WHITE}Repeat counter {Colors.YELLOW}({repeatcounter}/{repeat})\n")
            repeatcounter += 1

    except subprocess.CalledProcessError as e:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Unknown error: {str(e)}")
    except KeyboardInterrupt:
        print(f"\n\n{Colors.LIGHT_GREEN}[+] {Colors.WHITE}Scan interrupted\n")
    finally:
        signal.alarm(0)
    print(f"{Colors.WHITE}Copyright (c) 2023 Yzee4")

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

def is_valid_time(time):
    try:
        time = int(time)
        return 1 <= time
    except ValueError:
        return False

def is_valid_repeat(repeat):
    try:
        repeat = int(repeat)
        return 1 <= repeat
    except ValueError:
        return False  
    
# Flags management
def main():
    print(f"{interface}")
    global args
    global localnet 
    localnet = None
    global repeat
    repeat = 1
    global timescan
    timescan = None
    global command_list
    command_list = []

    parser = argparse.ArgumentParser(
        prog='dustox',
        epilog=f'{Colors.WHITE}Copyright (c) 2023 Yzee4',
        usage=f"dustox [-h] ip options: [-l] OR [-ip IP] filter options: [-p PORT] [-rp RANGEPORT] [-rip RANGEIP] control options: [-t TIME] [-r REPEAT]",
    )

    ip_group = parser.add_argument_group('ip options')    
    filter_group = parser.add_argument_group('filter options')
    control_group = parser.add_argument_group('control options')

    ip_group.add_argument('-l', '--localnet', action='store_true', help='scans the local network')
    ip_group.add_argument('-ip', help='scans specified address')

    filter_group.add_argument('-p', '--port', help='the target port')
    filter_group.add_argument('-rp', '--rangeport', help='the range of ports to scans')
    filter_group.add_argument('-rip', '--rangeip', help='the range of ip addresses to scans')

    control_group.add_argument('-t', '--time', help='set scanning time')
    control_group.add_argument('-r', '--repeat', help='set number of repetitions')

    parser.add_argument('-i', '--info', action='store_true', help='show script info')

    args = parser.parse_args()
    
    if args.info:
        print(f"""Coded by Yzee4
Produced on Python
Version 1.0.0 Linux
              
{Colors.LIGHT_GREEN}Dustox is a simple port scanner, with it you can see all
Open ports of local or specified IP. It features some filters 
that make your search easier. Its interface facilitates the 
visualization of information, as it is simple and contains 
elements that facilitate the interpretation of results
              
{Colors.WHITE}For more information visit project documentation on GitHub""")
        sys.exit()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit()

    if args.ip and args.localnet:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Use only one ip option")
        sys.exit()

    if not args.ip and not args.localnet:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Define ip address")
        sys.exit()

    if args.rangeip and not args.ip:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}For set range ip, fist specify an IP address with -ip")
        sys.exit()

    if args.rangeport and not args.port:
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}For set range port, fist specify a port value with -p")
        sys.exit()

    # Variables validation
    if args.ip and not is_valid_ip(args.ip):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid IP format")
        sys.exit()

    if args.port and not is_valid_port(args.port):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid port format")
        sys.exit()

    if args.rangeip and not is_valid_rangeip(args.ip, args.rangeip):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range IP format")
        sys.exit()

    if args.rangeport and not is_valid_rangeport(args.port, args.rangeport):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid range port format")
        sys.exit()

    if args.time and not is_valid_time(args.time):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid time format")
        sys.exit()

    if args.repeat and not is_valid_repeat(args.repeat):
        print(f"{Colors.LIGHT_RED}[-] {Colors.WHITE}Invalid repeat format")
        sys.exit()

    # Execute with arguments
    if args.ip:
        command_list.append(args.ip)


    if args.localnet:
        localnet = True

    if args.rangeip:
        command_list.clear()
        command_list.append(f"{args.ip}-{args.rangeip}")
        args.ip = f"{args.ip} ~ {args.rangeip}"

    if args.port:
        if not args.rangeport:
            command_list.append(f'-p {args.port}')

    if args.rangeport:
        command_list.append(f'-p {args.port}-{args.port}')

    if args.time:
        timescan = int(args.time)

    if args.repeat:
        repeat = int(args.repeat)

    scan_network()

# Interface
def interface_panel():
    global interface
    interface = f"""{Colors.YELLOW}Dustox {Colors.WHITE}| Simple Port Scanner{Colors.WHITE}\n
{Colors.LIGHT_BLUE}-| {Colors.WHITE}GitHub {Colors.LIGHT_GREEN}https://github.com/yzee4/Dustox{Colors.WHITE}\n"""

if __name__ == "__main__":
    Colors()
    verify_root()
    initializing_dustox()
    interface_panel()
    main()