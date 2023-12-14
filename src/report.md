# DO2_LinuxNetwork-1

- [Part 1. Инструмент ipcalc](#part-1-ipcalc-tool)
- [Part 2. Статическая маршрутизация между двумя машинами](#part-2-static-routing-between-two-machines)
- [Part 3. Утилита iperf3](#part-3-iperf3-utility)
- [Part 4. Сетевой экран](#part-4-network-firewall)
- [Part 5. Статическая маршрутизация сети](#part-5-static-network-routing)
- [Part 6. Динамическая настройка IP с помощью DHCP](#part-6-dynamic-ip-configuration-using-dhcp)
- [Part 7. NAT](#part-7-nat)
- [Part 8. Дополнительно. SSH Tunnels](#part-8-bonus-introduction-to-ssh-tunnels)

## Part 1. **ipcalc** tool

### Start a virtual machine (hereafter -- ws1)

### 1.1. Networks and Masks

### 1) network address of _192.167.38.54/13_

- The network address of *`192.167.38.54/13` → ```*192.160.0.0`
  To get this address there are few steps:
  - Convert `192.167.38.54` address to binary format → `11000000.10100111.00100110.00110110` → `11000000.10100`
  - Apply netmask : `11000000.10100000.00000000.00000000`
  - Convert back to decimal notation: `192.160.0.0`

![- ipcalc *192.167.38.54/13*](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled.png)

- ipcalc _192.167.38.54/13_

### 2) conversion of the mask _255.255.255.0_ to prefix and binary, _/15_ to normal and binary, _11111111.11111111.11111111.11110000_ to normal and prefix

**To get the results we can use `ipcalc…` command or just use binary calculator. But for best practice and understanding of course it is better to interact with linux cmd.**

- Prefix notation → /24 (because it has 24 bits set)
- Binary notation → `11111111.11111111.11111111.00000000`

![Untitled](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%201.png)

**/15 mask. To get normal and binary notation we have to convert binary `11111111.11111110.00000000.00000000` to decimal notation:**

- Normal notation → `255.254.0.0`
- Binary notation → `11111111.11111110.00000000.00000000`

![Untitled](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%202.png)

**\*11111111.11111111.11111111.11110000**:\*

- Normal notation → `255.255.255.240`
- Prefix notation → /28 (bcs it has 28 bits set)

![Untitled](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%203.png)

### 3) minimum and maximum host in _12.167.38.4_ network with masks: _/8_, _11111111.11111111.00000000.00000000_, _255.255.254.0_ and _/4_

**/8 case:**

- Address of network → `12.0.0.0`
- HostMin → `12.0.0.1`
- HostMax → `12.255.255.254`
- Total hosts → 16 777 214

![Untitled](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%204.png)

**/16 case:**

- Address of network → `12.167.0.0`
- HostMin → `12.167.0.1`
- HostMax → `12.167.255.254`
- Total hosts → 65 534

![Untitled](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%205.png)

**/23 case:**

- Address of network → `12.167.38.0`
- HostMin → `12.167.38.1`
- HostMax → `12.167.38.254`
- Total hosts → 510

![Untitled](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%206.png)

**/4 case:**

- Address of network → `0.0.0.0` (special address for choosing any network)
- HostMin → `0.0.0.1`
- HostMax → `15.255.255.254`
- Total hosts → 268 435 454

![`ipcalc 12.167.38.4/4`](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%207.png)

`ipcalc 12.167.38.4/4`

### 1.2. localhost

### Define and write in the report whether an application running on localhost can be accessed with the following IPs: _194.34.23.100_, _127.0.0.2_, _127.1.0.1_, _128.0.0.1_

To check the connection with loopback addresses (IPv4, IPv6) we should run:

- `ping -c 1 ::1`

![ping](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%208.png)

ping

![ping](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%209.png)

ping

Summary:

- `194.34.23.100` : IP-address is not a standard loopback address and is an external IP-address. An app on localhost will not be able at this address.
- `127.0.0.2` : IP-address is a loopback address and although this is not a standard loopback address. Due to a network configuration, an apps on localhost will be able to access this address
- `127.1.0.1` : This IP-address is also a loopback address, but also as previous one, not a standard one. So ping shows as that an apps on localhost will be able work. But it can cause various unexpected problems in other programs or scripts
- `128.0.0.1` : This IP address is not a loopback address and is an external IP-address. So, an app will not be available at this address.

### 1.3. Network ranges and segments

### Define and write in a report:

### 1) which of the listed IPs can be used as public and which only as private: _10.0.0.45_, _134.43.0.2_, _192.168.4.2_, _172.20.250.4_, _172.0.2.1_, _192.172.0.1_, _172.68.0.2_, _172.16.255.255_, _10.10.10.10_, _192.169.168.1_

To list the public IP addresses, we must look at the IP ranges defined for both. [https://ciscotips.com/private-public-ips](https://ciscotips.com/private-public-ips) indicates that there are 3 ranges for private and public IP addresses:

- `10.0.0.0/8` (that is, everything that starts with 10.).
  First range.
- `172.16.0.0/12` (that is, from `172.16.0.0` to `172.31.255.255` inclusive); Second range.
- `192.168.0.0/16` (that is, from `192.168.0.0` to `192.168.255.255` inclusive). Third range.

IP-addresses:

_`10.0.0.45` →_ Private. Starts with 10. and belongs _to first range._

_`134.43.0.2` → Public._

_`192.168.4.2` → Private. Belongs to third range._

_`172.20.250.4` → Private. Belongs to second range._

_`172.0.2.1` → Public._

_`192.172.0.1` → Public._

_`172.68.0.2` → Public._

_`172.16.255.255` → Private. Belongs to second range._

_`10.10.10.10` → Private. Belongs to first range._

_`192.169.168.1` → Public._

- So, the IPs that can be used as public are: _`134.43.0.2`_, _`172.0.2.1`_, _`192.172.0.1`_, _`172.68.0.2`_, and _`192.169.168.1`_.
- The IPs that can only be used as private are: _`10.0.0.45`_, _`192.168.4.2`_, _`172.20.250.4`_, _`172.16.255.255`_, and _`10.10.10.10` ._

Technically we can check it using command line:

### 2) which of the listed gateway IP addresses are possible for _10.10.0.0/18_ network: _10.0.0.1_, _10.10.0.2_, _10.10.10.10_, _10.10.100.1_, _10.10.1.255_

To find out the possible gateway IP-addresses for the `10.10.0.0/18` network. In a `/18` subnet, the IP range is from `10.10.0.0` to `10.10.63.255`. The gateway IP address is typically the first IP in the subnet, so it should be in the range `10.10.0.1` → `10.10.0.254`.

_`10.0.0.1`_ → Not possible (i.e. outside of the range)

_`10.10.0.2` → Possible <>_

_`10.10.10.10` → Possible <>_

_`10.10.100.1` → Not possible ><_

_`10.10.1.255` → Not possible ><_

The possible gateway IP addresses for the 10.10.0.0/18 network are 10.10.0.2 and 10.10.10.10.

Technically we can check it using command line:

## Part 2. Static routing between two machines

### Start two virtual machines (hereafter -- ws1 and ws2)

### View existing network interfaces with the `ip a` command

![Untitled](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2010.png)

![ws1 ip a ](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2011.png)

ws1 ip a

![ws2 ip a ](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2012.png)

ws2 ip a

### Describe the network interface corresponding to the internal network on both machines and set the following addresses and masks: ws1 - _192.168.100.10_, mask _/16 _, ws2 - _172.24.116.8_, mask _/12_

![ws1 - network configuration](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2013.png)

ws1 - network configuration

![ws2 - network configuration](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2014.png)

ws2 - network configuration

### Run the `netplan apply` command to restart the network service

![ws1 - configuration applying](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2015.png)

ws1 - configuration applying

![ws2 - configuration applying](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2016.png)

ws2 - configuration applying

### 2.1. Adding a static route manually

### Add a static route from one machine to another and back using a

`ip r add` command.

### Ping the connection between the machines

![ws1-2 pinging ](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2017.png)

ws1-2 pinging

- `sudo vim /etc/netplan/00-installer-config.yaml`
  - `addresses:`
    - `- 192.168.100.10/16`
  - `addresses:`
    - `- 172.24.116.8/12`
- `sudo netplan apply`
- `sudo ip route add 172.24.116.8 dev enp0s3`
- `sudo ip route add 196.168.100.10 dev enp0s3`

Output reports about successful ping given IP-addresses.

### 2.2. Adding a static route with saving

### Restart the machines

### Add static route from one machine to another using _etc/netplan/00-installer-config.yaml_ file

![ws1-2 static configuration for network](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2018.png)

ws1-2 static configuration for network

In configuration file added:

- `routes:`
  - `- to: 192.168.100.10`
  - `via: 172.24.116.8`

### Ping the connection between the machines

![ws-1 pinging ws2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2019.png)

ws-1 pinging ws2

![ws-2 pinging ws1](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2020.png)

ws-2 pinging ws1

- `ping 172.24.116.8`
- `ping 192.168.100.10`

## Part 3. **iperf3** utility

### 3.1. Connection speed

### Convert and write results in the report: 8 Mbps to MB/s, 100 MB/s to Kbps, 1 Gbps to Mbps

1.  8 Mbps to MB/s:
    Mbps stands for Megabits per second, and 1 byte is equal to 8 bits. To convert Mbps to MB/s, we need to divide by 8:
    8 Mbps = 8 Mbps / 8 = 1 MB/s

        So, 8 Mbps is equal to 1 MB/s.

2.  100 MB/s to Kbps:
    MB stands for Megabytes, and 1 Megabyte is equal to 1024 Kilobytes. To convert MB/s to Kbps, we need to multiply by 1024:
    100 MB/s = 100 MB/s \* 1024 = 102400 Kbps

        So, 100 MB/s is equal to 102400 Kbps.

3.  1 Gbps to Mbps:
    Gbps stands for Gigabits per second, and 1 Gigabit is equal to 1000 Megabits. To convert Gbps to Mbps, we need to multiply by 1000:
    1 Gbps = 1 Gbps \* 1000 = 1000 Mbps

        So, 1 Gbps is equal to 1000 Mbps.

### 3.2. **iperf3** utility

### Measure connection speed between ws1 and ws2

![ws1 - checking connection speed with iperf3 utility](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2021.png)

ws1 - checking connection speed with iperf3 utility

![ws2 - checking connection speed with iperf3 utility](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2022.png)

ws2 - checking connection speed with iperf3 utility

- `iperf3 -s m` - on ws1
- `iperf3 -c 192.168.100.10 -f K -R` - on ws2

## Part 4. Network firewall

### 4.1. **iptables** utility

### Create a _/etc/firewall.sh_ file simulating the firewall on ws1 and ws2:

### The following rules should be added to the file in a row:

### 1) on ws1 apply a strategy where a deny rule is written at the beginning and an allow rule is written at the end (this applies to points 4 and 5)

### 2) on ws2 apply a strategy where an allow rule is written at the beginning and a deny rule is written at the end (this applies to points 4 and 5)

### 3) open access on machines for port 22 (ssh) and port 80 (http)

### 4) reject _echo reply_ (machine must not ping, i.e. there must be a lock on OUTPUT)

### 5) allow _echo reply_ (machine must be pinged)

![ws1 - firewall configuration for network](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2023.png)

ws1 - firewall configuration for network

![ws2 - firewall configuration for network](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2024.png)

ws2 - firewall configuration for network

### Run the files on both machines with `chmod +x /etc/firewall.sh` and `/etc/firewall.sh` commands.

![ws1 - pinging each other](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2025.png)

ws1 - pinging each other

![ws2 - pinging each other](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2026.png)

ws2 - pinging each other

- In these section tasks deal with “filter” table of `iptables` and its rules. This tables is used for filtering packets. And this table is default. There are three type of rules:
  - input - these chains used to control behavior of incoming connections.
  - forward - these rules used to process incoming messages whose final destination is not the current server.
  - output - these chains used to deal with outcoming connections.
- How I understood the difference between first and second strategies is that both firewalls has their own rules. These rules determine how the firewall will process packets and will they be allowed or denied. For **ws1:**
  - **Specific rules:** The script includes specific rules to allow incoming traffic on port 22 (SSH) and port 80 (HTTP) using the `ACCEPT` target. This allows to establish SSH connection or access HTTP service on ws1.
  - **Ping configuration:** The script rejects outcoming ICMP echo reply packets on the OUTPUT chain, but it allows to reply on incoming ICMP on the INPUT chain, enabling to respond to ping requests from other devices.
  - **As a result** script’s strategy allows to connect via SSH (port 22) and HTTP (port 80). Also it allows to respond to ping requests from other devises. But script denies all outgoing ICMP packets.
- **For ws 2:**
  - **Specific rules:** As ws1 other devices can connect only via port 22 (SSH) and HTTP (80) using target `ACCEPT`
  - **Ping configuration:** The script allow all incoming packets. Then it rejects ICMP echo reply packets on the OUTPUT chain, which blocks outgoing ping response from ws2 to other devices.
    First strategy: rejects incoming packets, but responds to ping from other devices. Ping is not blocked by firewall.
    Second: allows to accept packets then rejects to respond to the ping. Packets blocked by firewall.

### 4.2. **nmap** utility

### Use **ping** command to find a machine which is not pinged, then use **nmap** utility to show that the machine host is up

![`nmap 172.24.116.8` on ws1](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2027.png)

`nmap 172.24.116.8` on ws1

_Check: nmap output should say: `Host is up`_.

- `nmap 172.24.116.8`

### Save dumps of the virtual machine images

## Part 5. Static network routing

### Start five virtual machines (3 workstations (ws11, ws21, ws22) and 2 routers (r1, r2))

### 5.1. Configuration of machine addresses

### Set up the machine configurations in _etc/netplan/00-installer-config.yaml_ according to the network in the picture.

![/etc/netplan/00-installer-config.yaml for ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2028.png)

/etc/netplan/00-installer-config.yaml for ws11

![/etc/netplan/00-installer-config.yaml for ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/%25D0%25A1%25D0%25BD%25D0%25B8%25D0%25BC%25D0%25BE%25D0%25BA_%25D1%258D%25D0%25BA%25D1%2580%25D0%25B0%25D0%25BD%25D0%25B0_2023-12-10_%25D0%25B2_5.51.23_PM.png)

/etc/netplan/00-installer-config.yaml for ws21

![/etc/netplan/00-installer-config.yaml for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2029.png)

/etc/netplan/00-installer-config.yaml for ws22

![/etc/netplan/00-installer-config.yaml for r1](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2030.png)

/etc/netplan/00-installer-config.yaml for r1

![/etc/netplan/00-installer-config.yaml for r2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2031.png)

/etc/netplan/00-installer-config.yaml for r2

![all machines](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2032.png)

all machines

### Restart the network service. If there are no errors, check that the machine address is correct with the `ip -4 a`command. Also ping ws22 from ws21. Similarly ping r1 from ws11.

![ip -4 a for ws11 and ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2033.png)

ip -4 a for ws11 and ws21

![ip -4 a for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2034.png)

ip -4 a for ws22

![ip -4 a for r1 and r2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2035.png)

ip -4 a for r1 and r2

![ping ws22 from ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2036.png)

ping ws22 from ws21

![ping r1 from ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2037.png)

ping r1 from ws11

### 5.2. Enabling IP forwarding.

### To enable IP forwarding, run the following command on the routers:

`sysctl -w net.ipv4.ip_forward=1`.

_With this approach, the forwarding will not work after the system is rebooted._

![`sysctl -w net.ipv4.ip_forward=1` for r1 and r2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2038.png)

`sysctl -w net.ipv4.ip_forward=1` for r1 and r2

### Open _/etc/sysctl.conf_ file and add the following line:

`net.ipv4.ip_forward = 1`_With this approach, IP forwarding is enabled permanently._

![adding line `net.ipv4.ip_forward = 1` for r1 and r2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2039.png)

adding line `net.ipv4.ip_forward = 1` for r1 and r2

### 5.3. Default route configuration

Here is an example of the `ip r' command output after adding a gateway:

```
default via 10.10.0.1 dev eth0
10.10.0.0/18 dev eth0 proto kernel scope link src 10.10.0.2
```

### Configure the default route (gateway) for the workstations. To do this, add `default` before the router's IP in the configuration file

![default gateway for ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2040.png)

default gateway for ws11

![default gateway for ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2041.png)

default gateway for ws21

![default gateway for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2042.png)

default gateway for ws22

### Call `ip r` and show that a route is added to the routing table

![ip r for ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2043.png)

ip r for ws11

![ip r for ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2044.png)

ip r for ws21

![ip r for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2045.png)

ip r for ws22

### Ping r2 router from ws11 and show on r2 that the ping is reaching. To do this, use the `tcpdump -tn -i eth1`

![`tcpdump -tn -i enp0s9` for r2 and `ping 10.20.0.1` for ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2046.png)

`tcpdump -tn -i enp0s9` for r2 and `ping 10.20.0.1` for ws11

### 5.4. Adding static routes

### Add static routes to r1 and r2 in configuration file. Here is an example for r1 route to 10.20.0.0/26:

```
# Add description to the end of the eth1 network interface:- to: 10.20.0.0
  via: 10.100.0.12
```

![adding static routes to r1 and r2sudo](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2047.png)

adding static routes to r1 and r2sudo

### Call `ip r` and show route tables on both routers. Here is an example of the r1 table:

```
10.100.0.0/16 dev eth1 proto kernel scope link src 10.100.0.11
10.20.0.0/26 via 10.100.0.12 dev eth1
10.10.0.0/18 dev eth0 proto kernel scope link src 10.10.0.1
```

![`ip r` for r1 and r2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2048.png)

`ip r` for r1 and r2

### Run `ip r list 10.10.0.0/[netmask]` and `ip r list 0.0.0.0/0` commands on ws11.

![ip r list - getting list of routes](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2049.png)

ip r list - getting list of routes

- IP address `0.0.0.0.0` is a non-routable IPv4 address that can be used for various purposes, mainly as a default or filler address. The IP address `0.0.0.0.0` means "this network." In the context of servers, `0.0.0.0.0` means "all IPv4 addresses on the local computer".

### 5.5. Making a router list

Here is an example of the **traceroute** utility output after adding a gateway:

```
1 10.10.0.1 0 ms 1 ms 0 ms
2 10.100.0.12 1 ms 0 ms 1 ms
3 10.20.0.10 12 ms 1 ms 3 ms
```

### Run the `tcpdump -tnv -i eth0` dump command on r1

### Use **traceroute** utility to list routers in the path from ws11 to ws21

![`traceroute 10.20.0.10` on ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2050.png)

`traceroute 10.20.0.10` on ws11

![`tcpdump -tn -i enp0s8` on r1](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2051.png)

`tcpdump -tn -i enp0s8` on r1

The **`traceroute`** command is a tool that helps determine the current location of a packet and identifies any issues in its delivery along a specified route. When dealing with routers and links from different organizations, checking these elements using the telnet command may not be feasible. Instead, **`traceroute`** and **`ping`** commands come in handy.

**`traceroute`** employs UDP packets and initiates the process by sending a package with Time To Live (TTL) set to 1. It then records the responding route's address. The procedure is repeated with increasing TTL values (e.g., TTL=2), and three packages are sent each time while measuring the response time.

These packets are directed to a randomly selected port, typically not in use. The traceroute utility considers the process complete when it receives a message from the target host indicating that the port is unavailable. This method helps trace the path of the packet and identify potential obstacles or delays.

- In this case: packages went three routes - from `10.10.0.1` to `10.10.0.2` and the final route - `10.20.0.10`
  - Package began from static gateway `10.10.0.1` to `10.10.0.2` and the final route wasn’t reached and we got message `time exceeded`
  - The next point was address `10.100.0.12`, packets were received on the destination node and the utility sends a response signaling the completion of the trace.

### 5.6. Using **ICMP** protocol in routing

### Run on r1 network traffic capture going through eth0 with the

`tcpdump -n -i eth0 icmp` command.

### Ping a non-existent IP (e.g. _10.30.0.111_) from ws11 with the

`ping -c 1 10.30.0.111` command.

![Capture network traffic passing through r1 with the command "tcpdump -n -i eth0 icmp" and ping from ws11 a non-existent IP 10.30.0.111 with the command "ping -c 1 10.30.0.111".](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2052.png)

Capture network traffic passing through r1 with the command "tcpdump -n -i eth0 icmp" and ping from ws11 a non-existent IP 10.30.0.111 with the command "ping -c 1 10.30.0.111".

## Part 6. Dynamic IP configuration using **DHCP**

### For r2, configure the **DHCP** service in the _/etc/dhcp/dhcpd.conf_ file:

### 1) specify the default router address, DNS-server and internal network address. Here is an example of a file for r2:

```
subnet 10.100.0.0 netmask 255.255.0.0 {}subnet 10.20.0.0 netmask 255.255.255.192
{    range 10.20.0.2 10.20.0.50;    option routers 10.20.0.1;    option domain-name-servers 10.20.0.1;}
```

![Configure the DHCP service configuration in the /etc/dhcp/dhcpd.conf file, specifying the default router address, DNS server, and internal network address.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2053.png)

Configure the DHCP service configuration in the /etc/dhcp/dhcpd.conf file, specifying the default router address, DNS server, and internal network address.

### 2) write `nameserver 8.8.8.8.` in a _resolv.conf_ file

![nameserver 8.8.8.8. in file resolv.conf.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2054.png)

nameserver 8.8.8.8. in file resolv.conf.

### Restart the **DHCP** service with `systemctl restart isc-dhcp-server`. Reboot the ws21 machine with `reboot` and show with `ip a` that it has got an address. Also ping ws22 from ws21.

![restarting DHCP service](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2055.png)

restarting DHCP service

![ip a for ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2056.png)

ip a for ws21

![ping ws22 from ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2057.png)

ping ws22 from ws11

### Specify MAC address at ws11 by adding to _etc/netplan/00-installer-config.yaml_:

`macaddress: 10:10:10:10:10:BA`, `dhcp4: true`

![specifying mac-address for ws11 in /etc/netplan/00-installer-config.yaml](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2058.png)

specifying mac-address for ws11 in /etc/netplan/00-installer-config.yaml

![ip a for ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2059.png)

ip a for ws11

### Сonfigure r1 the same way as r2, but make the assignment of addresses strictly linked to the MAC-address (ws11). Run the same tests

![Configured in /etc/dhcp/dhcpd.conf for r1 with MAC address hardwired.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2060.png)

Configured in /etc/dhcp/dhcpd.conf for r1 with MAC address hardwired.

![nameserver 8.8.8.8 in /etc/resolv.conf for r1](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2061.png)

nameserver 8.8.8.8 in /etc/resolv.conf for r1

![restarting DHCP service](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2062.png)

restarting DHCP service

![applying new configuration and pinging ws21 and ws22 from ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2063.png)

applying new configuration and pinging ws21 and ws22 from ws11

### Request ip address update from ws21

![ip a for ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2064.png)

ip a for ws21

![Commands used to update the IP on the ws21 workstation.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2065.png)

Commands used to update the IP on the ws21 workstation.

![ip a after configuring for ws21.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2066.png)

ip a after configuring for ws21.

The following DHCP server options were used:

- Option 1 - IP subnet mask;
- Option 3 - the default gateway;
- Option 51 defines for how long the IP address is leased to the client;

## Part 7. **NAT**

### In _/etc/apache2/ports.conf_ file change the line `Listen 80` to `Listen 0.0.0.0:80`on ws22 and r1, i.e. make the Apache2 server public

![configuring /etc/apache2/ports2.conf for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2067.png)

configuring /etc/apache2/ports2.conf for ws22

![configuring /etc/apache2/ports2.conf for r1](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2068.png)

configuring /etc/apache2/ports2.conf for r1

### Start the Apache web server with `service apache2 start` command on ws22 and r1

![starting server Apache with command apache2 start for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2069.png)

starting server Apache with command apache2 start for ws22

![starting server Apache with command apache2 start for r1](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2070.png)

starting server Apache with command apache2 start for r1

### Add the following rules to the firewall, created similarly to the firewall from Part 4, on r2:

### 1) delete rules in the filter table - `iptables -F`

### 2) delete rules in the "NAT" table - `iptables -F -t nat`

### 3) drop all routed packets - `iptables --policy FORWARD DROP`

![adding rules for [firewall.sh](http://firewall.sh) in r2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2071.png)

adding rules for [firewall.sh](http://firewall.sh) in r2

![activating [filrewall.sh](http://filrewall.sh) for r2](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2072.png)

activating [filrewall.sh](http://filrewall.sh) for r2

### Run the file as in Part 4

### Check the connection between ws22 and r1 with the `ping` command

_When running the file with these rules, ws22 should not ping from r1_

![Pinging from r1 and back fails due to a ban on r2.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2073.png)

Pinging from r1 and back fails due to a ban on r2.

### Add another rule to the file:

### 4) allow routing of all **ICMP** protocol packets

![Enable routing of all ICMP protocol packets to r2.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2074.png)

Enable routing of all ICMP protocol packets to r2.

### Run the file as in Part 4

### Check connection between ws22 and r1 with the `ping` command

_When running the file with these rules, ws22 should ping from r1_

![Ping from r1 to ws22 and back after adding a rule to allow routing of all ICMP protocol packets.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2075.png)

Ping from r1 to ws22 and back after adding a rule to allow routing of all ICMP protocol packets.

### Add two more rules to the file:

### 5) enable **SNAT**, which is masquerade all local ip from the local network behind r2 (as defined in Part 5 - network 10.20.0.0)

_Tip: it is worth thinking about routing internal packets as well as external packets with an established connection_

![Enable SNAT, for the ip for r2 and DNAT on the 8080 port of the r2 machine.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2076.png)

Enable SNAT, for the ip for r2 and DNAT on the 8080 port of the r2 machine.

### 6) enable **DNAT** on port 8080 of r2 machine and add external network access to the Apache web server running on ws22

### Run the file as in Part 4

### Check the TCP connection for **SNAT** by connecting from ws22 to the Apache server on r1 with the `telnet [address] [port]` command

![TCP connection for SNAT, connecting from ws22 to Apache server on r1 and back.](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2077.png)

TCP connection for SNAT, connecting from ws22 to Apache server on r1 and back.

### Check the TCP connection for **DNAT** by connecting from r1 to the Apache server on ws22 with the `telnet` command (address r2 and port 8080)

![TCP connection for SNAT, from r1 connect to the Apache server on ws22 with the telnet command (while accessing the r2 address and port 8080).](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2078.png)

TCP connection for SNAT, from r1 connect to the Apache server on ws22 with the telnet command (while accessing the r2 address and port 8080).

![whole capture](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2079.png)

whole capture

## Part 8. Bonus. Introduction to **SSH Tunnels**

### Run a firewall on r2 with the rules from Part 7

### Start the **Apapche** web server on ws22 on localhost only (i.e. in _/etc/apache2/ports.conf_ file change the line `Listen 80` to `Listen localhost:80`)

![configuring ws22 apache2 service](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2080.png)

configuring ws22 apache2 service

![apache2 service starting](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2081.png)

apache2 service starting

![configuring /etc/ssh/sshd_conf file for ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2082.png)

configuring /etc/ssh/sshd_conf file for ws11

![configuring /etc/ssh/sshd_conf file for ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2083.png)

configuring /etc/ssh/sshd_conf file for ws21

![configuring /etc/ssh/sshd_conf file for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2084.png)

configuring /etc/ssh/sshd_conf file for ws22

![restarting ssh service for ws11](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2085.png)

restarting ssh service for ws11

![restarting ssh service for ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2086.png)

restarting ssh service for ws21

![restarting ssh service for ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2087.png)

restarting ssh service for ws22

### Use _Local TCP forwarding_ from ws21 to ws22 to access the web server on ws22 from ws21

![connecting to ws22 from ws11 with local connection through port 80](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2088.png)

connecting to ws22 from ws11 with local connection through port 80

### Use _Remote TCP forwarding_ from ws11 to ws22 to access the web server on ws22 from ws11

![connecting to ws22 from ws11 with remote connection through port 80](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2089.png)

connecting to ws22 from ws11 with remote connection through port 80

### To check if the connection worked in both of the previous steps, go to a second terminal (e.g. with the Alt + F2) and run the `telnet 127.0.0.1 [local port]` command.

![telnet and uptime command for checking connection ws11 ws21](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2090.png)

telnet and uptime command for checking connection ws11 ws21

![telnet and uptime command for checking connection ws21 ws22](DO2_LinuxNetwork-1%2024921d39141e4a2c9d99a06910e3c221/Untitled%2091.png)

telnet and uptime command for checking connection ws21 ws22

**`ssh -L 8888:10.20.0.20:80 ws22@10.20.0.20`**

Here's what each part of the command does:

- **`ssh`**: This is the Secure Shell (SSH) command-line client. It's used to connect to a remote server and encrypt the communication between your local machine and the server.
- **`L`**: This option tells SSH to listen on a specific port on your local machine. In this case, it's listening on port 8888.
- **`8888`**: This is the port number that SSH will listen on. Any incoming connections to this port will be forwarded to the remote server.
- **`:10.20.0.20:80`**: This is the address and port of the remote server that you want to connect to. The **`:`** separates the hostname or IP address from the port number. In this case, we're connecting to a server with the IP address **`10.20.0.20`** on port **`80`**.
- **`ws22@10.20.0.20`**: This is the username and hostname or IP address of the remote server. The **`@`** symbol separates the username from the hostname or IP address. In this case, the username is **`ws22`** and the hostname or IP address is **`10.20.0.20`**.
