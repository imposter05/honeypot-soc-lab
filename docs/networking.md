# Networking

## Default: this computer only

Every decoy and the dashboard bind to 127.0.0.1. Nothing is reachable
from other machines. `hive doctor` warns if either address is not
loopback, and `hive serve` prints a warning at startup.

| Service | Port | Protocol notes |
|---|---|---|
| Dashboard/API | 8000 | HTTP and WebSocket (`/api/ws`) |
| SSH | 2222 | banner `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` |
| HTTP | 8080 | HTTP/1.1 |
| FTP | 2121 | control channel; passive data on 30000-30009 |
| SMB | 4450 | |
| MySQL | 3307 | sends a server greeting |
| Redis | 6380 | RESP |

Ports above 1024 are used so no root access is needed. The original bound
FTP passive data to a random port on every interface; it now uses
`ftp.passive_port_min` to `ftp.passive_port_max` on the decoy address,
and the data connection is accepted only from the same address as the
control connection.

## What each event records

Source address and port, destination address and port, protocol, UTC
timestamp, the sensor ID and whether the source is in `lab.source_ranges`.

## Lab sources on one machine

On Linux the whole 127.0.0.0/8 range works without setup. `labtest`
gives each scenario its own address (for example 127.42.102.11), so rule
windows, cases and restrictions from one scenario do not affect another.
On macOS only 127.0.0.1 exists until you add aliases:

```bash
sudo ./scripts/mac-loopback-aliases.sh add     # 127.0.0.10 to 127.0.0.99, until reboot
./scripts/mac-loopback-aliases.sh status
sudo ./scripts/mac-loopback-aliases.sh remove
```

labtest then takes addresses from that pool. It also asks the lab whether
each address has been quiet for longer than the longest rule window,
suppression period and case grouping window (31 minutes with the default
rules), and refuses to run rather than reuse a busy address, because rule
state and case grouping are per address. `-source X` runs a single
scenario from one address and needs `-only`.

## Capturing traffic

This capture command was tested with the lab (it recorded the FTP control
connection on 2121, passive data on 30000 and Redis on 6380):

```bash
sudo tcpdump -i lo -nn -w evidence/pcaps/$(date -u +%Y%m%dT%H%M%SZ).pcap \
  'tcp and (port 2222 or port 8080 or port 2121 or portrange 30000-30009 or port 4450 or port 3307 or port 6380)'
```

On macOS the loopback interface is `lo0`. Stop with Ctrl-C, then open
the file in Wireshark or read it with `tcpdump -nn -r file.pcap`. Record
the capture file name, the labtest run ID and the case numbers together
in `evidence/network-tests/`, so a report can point at all three.

Captures contain whatever was sent, including passwords typed into the
decoys. Keep them out of public repositories unless they only contain
test credentials.

## Moving the decoys to a lab network

Only do this on a network you control, for example a host-only network
between your computer and a virtual machine you attack from.

1. Set `network.honeypot_host` to the host-only address (for example
   192.168.56.1). Leave `network.management_host` at 127.0.0.1.
2. Add the attacker VM's range to `lab.source_ranges` if you want its
   events marked as lab traffic.
3. Allow only that network to reach the decoy ports in the host firewall.
4. Run `hive doctor` and read its warnings.

Do not put the decoys on a public address with this build. It has not
been hardened or tested for that.
