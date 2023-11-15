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
import subprocess

# Define colors
def colors():
    global white, cyan, lightred, lightgreen, yellow, lightblue, pink
    white = '\033[0;97m'
    cyan = '\033[0;36m'
    lightred = '\033[0;91m'
    lightgreen = '\033[0;92m'
    yellow = '\033[0;93m'
    lightblue = '\033[0;94m'
    pink = '\033[0;95m'
colors()

# Check Termux user
def check_user_data():
    global user_data
    if os.path.exists('/data/data/com.termux'):
        user_data = 'Termux'
    else:
        user_data = None
check_user_data()

def main():
    if not user_data == 'Termux':
        if os.geteuid() != 0:
            print(f"{lightred}[-] {white}Execute as root mode. Use {lightgreen}'sudo python3 install.py'{white}.")
            exit(1)

    # Define user data path
    if not user_data == 'Termux':
        zip_file = "dustox.zip"
        dest_dir = "/usr/local/bin"
        dustox_executable = "/usr/local/bin/dustox"
        dustox_py_executable = "/usr/local/bin/dustox.py"

    if user_data == 'Termux':
        zip_file = "dustox.zip"
        dest_dir = "/data/data/com.termux/files/usr/bin"
        dustox_executable = "/data/data/com.termux/files/usr/bin/dustox"
        dustox_py_executable = "/data/data/com.termux/files/usr/bin/dustox.py"

    if os.path.exists(dustox_executable) and os.path.exists(dustox_py_executable):
        print(f"{lightgreen}[+] {white}Dustox already installed. Use {lightgreen}'dustox' {white}to run.")
        exit(0)

    if not os.path.exists(zip_file):
        print(f"{lightred}[-] {white}File not found.")
        exit(1)

    with open(os.devnull, 'w') as nullfile:
        result = subprocess.run(["unzip", zip_file, "-d", dest_dir], stdout=nullfile, stderr=nullfile)

    if result.returncode == 0:
        os.chmod(dustox_executable, 0o755)
        os.chmod(dustox_py_executable, 0o755)
        print(f"{lightgreen}[+] {white}Dustox has been installed. Use {lightgreen}'dustox' {white}to run.")
        if not os.path.exists(dustox_py_executable):
            print(f"{lightred}[-] {white}dustox.py was not found in the package.")
        exit(0)
main()
