<h1 align="center">Sainwha</h1>

[![License][1]][2]

[1]: https://img.shields.io/badge/License-MIT-brightgreen.svg

[2]: LICENSE

 How it works is simple, the program sends deauthentication
 packets to the network. Connected clients are deauthenticated and 
 cannot be reconnected unless the attack is stopped. [See more](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack).

<p align="center">
  <img src="docs/Sainwha-1.png" alt="Sainwha" style="border: 1px solid #000000;">
</p>

> [!CAUTION]
> Your network card may be disabled while the program is running.

> [!NOTE]
> The program is under development, possibly has errors.

# Installation
> Open Linux terminal

```terminal
git clone https://github.com/yzee4/Sainwha.git
```

<h1 align="center">Attack example</h1>
<h4 align="center">This attack was carried out in a controlled environment.</h4>
<p align="center" style="text-align: center;">
  <img src="docs/Sainwha-2.png" alt="Sainwha">
</p>
<h4 align="center">First we define the scanning interface, then we check and configure the network to attack. The attack is launched and clients are disconnected until the attack is stopped.</h4>

# Running
> Open Linux terminal

<h4>2. Go to Sainwha folder</h4>

```terminal
cd Sainwha
```
<h4>3. Run with python</h4>

```terminal
python3 sainwha.py
```

<h1 align="center">Help menu</h1>
<p align="center" style="text-align: center;">
  <img src="docs/Sainwha-3.png" alt="Sainwha" style="border: 1px solid #000000; margin-bottom: 10px;">
</p>
<h4 align="center">The help menu can be opened within the program with 'help'</h4>

<h2>Requirements</h2>

> All requirements can be installed directly on the terminal

   - `Python3` For running program. To install use `sudo apt install python3`
   - `Nmap` For scans all networks and sends deauthentication packets. To  install use `sudo apt install nmap`
   - `Net-tools` For set interface to scans. To install use `sudo apt install net-tools`
