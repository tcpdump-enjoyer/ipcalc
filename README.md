# ipcalc

A Python tool for network calculations and subnetting.

```
> python3 ipcalc.py 192.168.1.1/24

192.168.1.0/24
address    : 192.168.1.0    
mask       : 255.255.255.0  
length     : 24             
hosts      : 254            
```

## Installation

**Clone the repo**

```
git clone https://github.com/tcpdump_enjoyer/ipcalc.git
```

## Usage

```
ipcalc.py [-h] [-b] [-a] addr[/mask] [supernet|subnet]
```

**Syntax**

`addr` -- IPv4 address in dotted decimal notation (default: 192.168.1.1)  
`mask` -- IPv4 subnet mask in dotted decimal or CIDR notation (default: 255.255.255.0 or 24)  

**Options**

`supernet` -- IPv4 subnet mask in dotted decimal or CIDR notation

```
> python3 ipcalc.py 192.168.1.1/24 255.255.240.0

192.168.0.0/20
address    : 192.168.1.0    
mask       : 255.255.255.0  
length     : 24             
hosts      : 254            
└── 192.168.1.0/24
    address    : 192.168.0.0    
    mask       : 255.255.240.0  
    length     : 20             
    hosts      : 4094           
```

`subnet` -- IPv4 subnet mask in dotted decimal or CIDR notation

```
> python3 ipcalc.py 192.168.1.1/255.255.255.0 25

192.168.1.0/24
address    : 192.168.1.0    
mask       : 255.255.255.0  
length     : 24             
hosts      : 254            
├── 1: 192.168.1.0/25          
└── 2: 192.168.1.128/25
```

**Flags**

`-a, --all` -- Show hidden attributes (wildcard, min, max, broadcast and usage)

```
> python3 ipcalc.py 192.168.1.1/24 25 -a

192.168.1.0/24
address    : 192.168.1.0    
min        : 192.168.1.1    
max        : 192.168.1.254  
broadcast  : 192.168.1.255  
mask       : 255.255.255.0  
wildcard   : 0.0.0.255      
length     : 24             
hosts      : 254            
usage      : Private use (RFC1918)
```

`-b, --binary` -- Show binary notation

```
> python3 ipcalc.py 192.168.1.1/24 -b

192.168.1.0/24
address    : 192.168.1.0     11000000.10101000.00000001.00000000
mask       : 255.255.255.0   11111111.11111111.11111111.00000000
length     : 24             
hosts      : 254            
```

**Example**

```
> python3 ipcalc.py 192.168.1.1/24 25 -a -b

192.168.1.0/24
address    : 192.168.1.0     11000000.10101000.00000001.00000000
min        : 192.168.1.1     11000000.10101000.00000001.00000001
max        : 192.168.1.254   11000000.10101000.00000001.11111110
broadcast  : 192.168.1.255   11000000.10101000.00000001.11111111
mask       : 255.255.255.0   11111111.11111111.11111111.00000000
wildcard   : 0.0.0.255       00000000.00000000.00000000.11111111
length     : 24             
hosts      : 254            
usage      : Private use (RFC1918)         
├── 1: 192.168.1.0/25
    address    : 192.168.1.0     11000000.10101000.00000001.00000000
    min        : 192.168.1.1     11000000.10101000.00000001.00000001
    max        : 192.168.1.126   11000000.10101000.00000001.01111110
    broadcast  : 192.168.1.127   11000000.10101000.00000001.01111111
    mask       : 255.255.255.128 11111111.11111111.11111111.10000000
    wildcard   : 0.0.0.127       00000000.00000000.00000000.01111111
    length     : 25             
    hosts      : 126            
    usage      : Private use (RFC1918)          
└── 2: 192.168.1.128/25       
    address    : 192.168.1.128   11000000.10101000.00000001.10000000
    min        : 192.168.1.129   11000000.10101000.00000001.10000001
    max        : 192.168.1.254   11000000.10101000.00000001.11111110
    broadcast  : 192.168.1.255   11000000.10101000.00000001.11111111
    mask       : 255.255.255.128 11111111.11111111.11111111.10000000
    wildcard   : 0.0.0.127       00000000.00000000.00000000.01111111
    length     : 25             
    hosts      : 126            
    usage      : Private use (RFC1918)
```

## Customize

When `-a, --all` is omitted, only few network attributes are displayed :
- address -- network address or ID  
- mask -- network mask  
- length -- network mask (CIDR notation, see [RFC4632](https://datatracker.ietf.org/doc/html/rfc4632))  
- (optional) wildcard -- inverted network mask  
- (optional) min -- lowest usable IP address  
- (optional) max -- highest usable IP address  
- (optional) broadcast -- broadcast address  
- hosts -- maximum number of addressable hosts  
- (optional) usage -- see [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

This can be changed by modifying `DEFAULT_HIDDEN_ATTRIBUTES` :

```
DEFAULT_HIDDEN_ATTRIBUTES = ["wildcard", "usage"]
---

> python3 ipcalc.py 192.168.1.1/255.255.255.0    

192.168.1.0/24
address    : 192.168.1.0    
min        : 192.168.1.1    
max        : 192.168.1.254  
broadcast  : 192.168.1.255  
mask       : 255.255.255.0  
length     : 24             
hosts      : 254            
```

## Roadmap

- [x] IPv4 support
- [ ] IPv6 support

## License

Distributed under the GNU General Public License v3.0.
