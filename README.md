# ![OpenGFW](docs/logo.png)

[![License][1]][2]

[1]: https://img.shields.io/badge/License-MIT-brightgreen.svg

[2]: LICENSE

 How it works is simple, the program sends deauthentication
 packets to the network. Connected clients are deauthenticated and 
 cannot be reconnected unless the attack is stopped. [See more](https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack).


> [!CAUTION]
> Your network card may be disabled while the program is running

> [!NOTE]
> The program is under development, possibly has errors

## What Sainwha does?

- Full IP/TCP reassembly, various protocol analyzers
    - HTTP, TLS, DNS, SSH, and many more to come
    - "Fully encrypted traffic" detection for Shadowsocks,
      etc. (https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf)
    - Trojan (proxy protocol) detection based on Trojan-killer (https://github.com/XTLS/Trojan-killer)
    - [WIP] Machine learning based traffic classification
- Full IPv4 and IPv6 support
- Flow-based multicore load balancing
- Connection offloading
- Powerful rule engine based on [expr](https://github.com/expr-lang/expr)
- Flexible analyzer & modifier framework
- Extensible IO implementation (only NFQueue for now)
- [WIP] Web UI

## Use cases

- Ad blocking
- Parental control
- Malware protection
- Abuse prevention for VPN/proxy services
- Traffic analysis (log only mode)

## Usage

### Build

```shell
go build
```

### Run

```shell
export OPENGFW_LOG_LEVEL=debug
./OpenGFW -c config.yaml rules.yaml
```

### Example config

```yaml
io:
  queueSize: 1024
  local: true # set to false if you want to run OpenGFW on FORWARD chain

workers:
  count: 4
  queueSize: 16
  tcpMaxBufferedPagesTotal: 4096
  tcpMaxBufferedPagesPerConn: 64
  udpMaxStreams: 4096
```

### Example rules

[Analyzer properties](docs/Analyzers.md)

For syntax of the expression language, please refer
to [Expr Language Definition](https://expr-lang.org/docs/language-definition).

```yaml
- name: block v2ex http
  action: block
  expr: string(http?.req?.headers?.host) endsWith "v2ex.com"

- name: block v2ex https
  action: block
  expr: string(tls?.req?.sni) endsWith "v2ex.com"

- name: block shadowsocks
  action: block
  expr: fet != nil && fet.yes

- name: block trojan
  action: block
  expr: trojan != nil && trojan.yes

- name: v2ex dns poisoning
  action: modify
  modifier:
    name: dns
    args:
      a: "0.0.0.0"
      aaaa: "::"
  expr: dns != nil && dns.qr && any(dns.questions, {.name endsWith "v2ex.com"})
```

#### Supported actions

- `allow`: Allow the connection, no further processing.
- `block`: Block the connection, no further processing. Send a TCP RST if it's a TCP connection.
- `drop`: For UDP, drop the packet that triggered the rule, continue processing future packets in the same flow. For
  TCP, same as `block`.
- `modify`: For UDP, modify the packet that triggered the rule using the given modifier, continue processing future
  packets in the same flow. For TCP, same as `allow`.
