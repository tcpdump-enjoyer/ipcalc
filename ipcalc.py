#!/usr/bin/python3

DEFAULT_NETWORK_ADDR = "192.168.1.1"
DEFAULT_NETWORK_MASK = "24"
DEFAULT_HIDDEN_ATTRIBUTES = ["min", "max", "broadcast", "wildcard", "usage"]

import argparse
import re
import sys

# matches: 192.168.1.1 or 192.168.1.1/24 or 192.168.1.0/255.255.255.0
# group 1: 192.168.1.1
# group 2: 24 or 255.255.255.0
REGEX_NETWORK = "^((?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}))(?:\/((?:3[0-2]|[12]\d|\d)|(?:(?:(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})))))?$"
# matches: 24 or 255.255.255.0
REGEX_SUBNET = "^((?:3[0-2]|[12]\d|\d)|(?:(?:(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}))))$"
REGEX_NETMASK_CIDR = "^(?:3[0-2]|[12]\d|\d)$"
REGEX_NETMASK_DOTTED_DECIMAL = "^(?:(?:(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})))$"

def dotted_decimal_to_binary(address: str) -> str:
    """
    Convert dotted decimal notation into binary notation.  
    Example: `"192.168.1.1"` => `"11000000101010000000000100000001"`
    """
    result = ""
    for byte in address.split("."):
        result += bin(int(byte))[2:].rjust(8, "0") # remove '0b' and stuff with '0' for a full 8-bit representation
    return result


def dotted_decimal_to_dotted_binary(address: str) -> str:
    """
    Convert dotted decimal notation into dotted binary notation.  
    Example: `"192.168.1.1"` => `"11000000.10101000.00000001.00000001"`
    """
    result = []
    for byte in address.split("."):
        byte = bin(int(byte))[2:].rjust(8, "0") # remove '0b' and stuff with '0' for a full 8-bit representation
        result.append(byte)
    result = ".".join(result)
    return result


def binary_to_dotted_decimal(bitstring: str) -> str:
    """
    Convert binary notation into dotted decimal notation.  
    Example: `"11000000101010000000000100000001"` => `"192.168.1.1"`
    """
    bytes = [bitstring[i:i+8] for i in range(0, len(bitstring), 8)]
    return ".".join([str(int(byte, 2)) for byte in bytes])


def cidr_to_dotted_decimal(subnet_mask: str) -> str:
    """
    Convert CIDR notation into dotted decimal notation.  
    Example: `"24"` => `"255.255.255.0"`
    """
    bitstring = "1" * int(subnet_mask)
    bitstring += "0" * (32 - int(subnet_mask))
    byte_array = [bitstring[i:i+8] for i in range(0, len(bitstring), 8)]
    result = [str(int(byte, 2)) for byte in byte_array]
    result = ".".join(result)
    return result


def dotted_decimal_to_cidr(subnet_mask: str) -> str:
    """
    Convert dotted decimal notation into CIDR notation.  
    Example: `"255.255.255.0"` => `"24"`
    """
    return str(dotted_decimal_to_binary(subnet_mask).count("1"))


def wildcard(mask: str, binary: bool = False) -> str:
    """
    Return the inverted mask from bit string `mask`. Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.  
    Example: `"11111111111111111111111100000000"` => `"00000000000000000000000011111111"`
    """
    result = "".join(["0" if bit == "1" else "1" for bit in mask])
    return result if binary else binary_to_dotted_decimal(result)


def network_address(address: str, subnet_mask: str, binary: bool = False) -> str:
    """
    Return the network address given `address` and `subnet_mask` in dotted decimal notation. Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.  
    Example: `"192.168.1.1/24"` => `"192.168.1.0"`
    """
    result = ""
    addr = dotted_decimal_to_binary(address)
    mask = dotted_decimal_to_binary(subnet_mask)
    for i in range(32):
        bit = int(addr[i]) & int(mask[i])
        result += str(bit)
    return result if binary else binary_to_dotted_decimal(result)


def network_broadcast(address: str, subnet_mask: str, binary: bool = False) -> str:
    """
    Return the broadcast address given `address` and `subnet_mask` in dotted decimal notation. Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.  
    Example: `"192.168.1.0/24"` => `"192.168.1.255"`
    """
    result = ""
    addr = dotted_decimal_to_binary(address)
    mask = dotted_decimal_to_binary(subnet_mask)
    for i in range(32):
        match mask[i]:
            case "1": result += addr[i]
            case "0": result += "1"
    return result if binary else binary_to_dotted_decimal(result)


def network_min(address: str, subnet_mask: str, binary: bool = False) -> str:
    """
    Return the first network address given `address` and `subnet_mask` in dotted decimal notation. Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.  
    Example: `"192.168.1.0/24"` => `"192.168.1.1"`
    """
    result = network_address(address, subnet_mask, binary=True)[:-1] + "1"
    return result if binary else binary_to_dotted_decimal(result)


def network_max(address: str, subnet_mask: str, binary: bool = False) -> str:
    """
    Return the last network address given `address` and `subnet_mask` in dotted decimal notation. Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.  
    Example: `"192.168.1.0/24"` => `"192.168.1.254"`
    """
    result = network_broadcast(address, subnet_mask, binary=True)[:-1] + "0"
    return result if binary else binary_to_dotted_decimal(result)


def network_hosts(prefix_length: str) -> str:
    """
    Return the number of hosts for a given prefix length. If `prefix_length == 31` then 2 is returned, according to RFC3021.  
    Example: `"24"` => `"254"`
    """
    match int(prefix_length):
        case 0: return "all"
        case 31: return "2 (RFC3021)"
        case 32: return "1"
        case _: return str(2 ** ( 32 - int(prefix_length) ) - 2)

class Network():
    def __init__(self, address: str, subnet_mask: str):
        """
        Object representing an IPv4 network.  

        Arguments  
        - address -- dotted-decimal notation of an IPv4 address.  
        - subnet_mask -- dotted-decimal or CIDR notation of an IPv4 network mask  

        Attributes  
        - address -- network address or ID  
        - mask -- network mask  
        - length -- network mask (CIDR notation, see RFC4632)  
        - (optional) wildcard -- inverted network mask  
        - (optional) min -- lowest usable IP address  
        - (optional) max -- highest usable IP address  
        - (optional) broadcast -- broadcast address  
        - hosts -- maximum number of addressable hosts  
        - (optional) usage -- see https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
        """
        self.__set_mask(subnet_mask)
        self.__set_length(subnet_mask)
        self.__set_wildcard()
        self.__set_address(address)
        self.__set_broadcast()
        self.__set_min()
        self.__set_max()
        self.__set_hosts()
        self.__set_usage()

    def __set_address(self, address):
        self.address = network_address(address, self.mask)
        
    def __set_mask(self, subnet_mask):
        self.mask = subnet_mask if re.match(REGEX_NETMASK_DOTTED_DECIMAL, subnet_mask) else cidr_to_dotted_decimal(subnet_mask)
        
    def __set_length(self, subnet_mask):
        self.length = subnet_mask if re.match(REGEX_NETMASK_CIDR, subnet_mask) else dotted_decimal_to_cidr(subnet_mask)
        
    def __set_wildcard(self):
        self.wildcard = wildcard(dotted_decimal_to_binary(self.mask))
        
    def __set_broadcast(self):
        self.broadcast = network_broadcast(self.address, self.mask)
        
    def __set_min(self):
        self.min = network_min(self.address, self.mask)
        
    def __set_max(self):
        self.max = network_max(self.address, self.mask)
        
    def __set_hosts(self):
        self.hosts = network_hosts(self.length)

    def __set_usage(self):
        # https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
        if self.belongs_to("10.0.0.0", "8"):
            self.usage = "Private use (RFC1918)"
        elif self.belongs_to("100.64.0.0", "10"):
            self.usage = "Shared Address Space (RFC6598)"
        elif self.belongs_to("127.0.0.0", "8"):
            self.usage = "Loopback (RFC1122, section 3.2.1.3)"
        elif self.belongs_to("169.254.0.0", "16"):
            self.usage = "Link Local (RFC3927)"
        elif self.belongs_to("172.16.0.0", "12"):
            self.usage = "Private use (RFC1918)"
        elif self.belongs_to("192.0.0.0", "24"):
            self.usage = "IETF Protocol Assignments (RFC6890, section 2.1)"
        elif self.belongs_to("192.0.0.0", "29"):
            self.usage = "IPv4 Service Continuity Prefix (RFC7335)"
        elif self.belongs_to("192.0.0.8", "32"):
            self.usage = "IPv4 dummy address (RFC7600)"
        elif self.belongs_to("192.0.0.9", "32"):
            self.usage = "Port Control Protocol Anycast (RFC7723)"
        elif self.belongs_to("192.0.0.10", "32"):
            self.usage = "Traversal Using Relays around NAT Anycast (RFC8155)"
        elif self.belongs_to("192.0.0.170", "32") or self.belongs_to("192.0.0.171", "32"):
            self.usage = "NAT64/DNS64 Discovery (RFC7050, section 2.2)"
        elif self.belongs_to("192.0.2.0", "24"):
            self.usage = "Documentation (TEST-NET-1) (RFC5737)"
        elif self.belongs_to("192.31.196.0", "24"):
            self.usage = "AS112-v4 (RFC7535)"
        elif self.belongs_to("192.52.193.0", "24"):
            self.usage = "AMT (RFC7450)"
        elif self.belongs_to("192.88.99.0", "24"):
            self.usage = "6to4 Relay Anycast (RFC7526) (deprecated since 2015-03)"
        elif self.belongs_to("192.168.0.0", "16"):
            self.usage = "Private use (RFC1918)"
        elif self.belongs_to("192.175.48.0", "24"):
            self.usage = "Direct Delegation AS112 Service (RFC7534)"
        elif self.belongs_to("198.18.0.0", "15"):
            self.usage = "Benchmarking (RFC2544)"
        elif self.belongs_to("198.51.100.0", "24"):
            self.usage = "Documentation (TEST-NET-2) (RFC5737)"
        elif self.belongs_to("203.0.113.0", "24"):
            self.usage = "Documentation (TEST-NET-3) (RFC5737)"
        elif self.belongs_to("240.0.0.0", "4"):
            self.usage = "Multicast (RFC1112, section 4)"
        elif self.belongs_to("255.255.255.255", "32"):
            self.usage = "Limited Broadcast (RFC8190)"
        else:
            self.usage = None
        
    def belongs_to(self, address: str, prefixlength: str) -> bool:
        """
        Return `True` if self is a subnet of the given network.\n
        """
        if network_address(self.address, cidr_to_dotted_decimal(prefixlength)) == network_address(address, cidr_to_dotted_decimal(prefixlength))\
        and int(self.length) >= int(prefixlength):
            return True
        else:
            return False
        
        
def display_network_info(network: Network):
    """
    Display network information. Optional attributes are hidden unless `args.all` is `True`.
    """
    attributes = [
        ["address", network.address.ljust(15), dotted_decimal_to_dotted_binary(network.address)],
        ["min", network.min.ljust(15), dotted_decimal_to_dotted_binary(network.min)], # optional
        ["max", network.max.ljust(15), dotted_decimal_to_dotted_binary(network.max)], # optional
        ["broadcast", network.broadcast.ljust(15), dotted_decimal_to_dotted_binary(network.broadcast)], # optional
        ["mask", network.mask.ljust(15), dotted_decimal_to_dotted_binary(network.mask)],
        ["wildcard", network.wildcard.ljust(15), dotted_decimal_to_dotted_binary(network.wildcard)], # optional
        ["length", network.length, None],
        ["hosts", network.hosts, None],
        ["usage", network.usage, None], # optional
    ]
    for attribute in attributes:
        name: str = attribute[0]
        if not args.all and name in DEFAULT_HIDDEN_ATTRIBUTES:
            # skip hidden attributes
            continue
        value_dec: str = attribute[1]
        value_bin: str = attribute[2]
        if not value_dec:
            # skip "usage" attribute (among others) if not set
            continue
        if args.binary:
            if name in ["length", "hosts", "usage"]:
                # no binary values for those attributes
                print(name.ljust(10), ":", value_dec.ljust(15))
            else:
                print(name.ljust(10), ":", value_dec.ljust(15), value_bin)
        else:
            print(name.ljust(10), ":", value_dec.ljust(15))


def display_supernet_info(network: Network, supernet_length: str):
    """
    Show informations for supernet of length `supernet_length`.
    """
    supernet = Network(network.address, supernet_length)
    print("---")
    print(f"{supernet.address}/{supernet_length}")
    print(f"└─ {network.address}/{network.length}")
    display_network_info(supernet)
    

def display_subnet_info(network: Network, subnet_length: str):
    """
    Show all subnets of length `subnet_length`.
    """
    next_subnet = Network(network.address, subnet_length)
    count = 2 ** (int(subnet_length) - int(network.length))
    print("---")
    print(f"{network.address}/{network.length}")
    for i in range(count):
        if i == count-1:
            print(f"└─ {i+1}: {next_subnet.address}/{next_subnet.length}")
        else:
            print(f"├─ {i+1}: {next_subnet.address}/{next_subnet.length}")
        if args.all:
            display_network_info(next_subnet)
        hops = [1, 128, 64, 32, 16, 8, 4, 2][int(subnet_length) % 8]
        if 0 < int(next_subnet.length) and int(next_subnet.length) <= 8:
            byte_index = 0
        elif 8 < int(next_subnet.length) and int(next_subnet.length) <= 16:
            byte_index = 1
        elif 16 < int(next_subnet.length) and int(next_subnet.length) <= 24:
            byte_index = 2
        elif 24 < int(next_subnet.length) and int(next_subnet.length) <= 32:
            byte_index = 3
        else:
            sys.exit(f"error: invalid length {next_subnet.length}")
        next_subnet_addr = ""
        for i, byte in enumerate(next_subnet.address.split(".")):
            if i == byte_index:
                next_subnet_addr += str(int(byte) + hops)
            else:
                next_subnet_addr += byte
            if i < 3:
                next_subnet_addr += "."
        next_subnet = Network(next_subnet_addr, subnet_length)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("network", metavar="addr[/mask]", nargs='?', type=str, default=f"{DEFAULT_NETWORK_ADDR}/{DEFAULT_NETWORK_MASK}")
    parser.add_argument("prefixlength", metavar="supernet|subnet", nargs='?', type=str, default=None)
    parser.add_argument("-b", "--binary", action="store_true", help="show binary notation")
    parser.add_argument("-a", "--all", action="store_true", help="show all informations")
    
    global args
    args = parser.parse_args()

    try:
        addr = re.match(REGEX_NETWORK, args.network).group(1)
        mask = re.match(REGEX_NETWORK, args.network).group(2)
        if not mask:
            mask = DEFAULT_NETWORK_MASK
    except:
        sys.exit(f"error: invalid value for 'network': {args.network}")
    
    if args.prefixlength:
        try:
            prefixlength = re.match(REGEX_SUBNET, args.prefixlength).group(1)
        except:
            sys.exit(f"error: invalid value for 'prefixlength': {args.prefixlength}")
    else:
        prefixlength = None
    
    # at this point, expect valid inputs for addr, mask and prefixlength
    # default: addr:"192.168.1.1", mask:"24", prefixlength:None

    network = Network(addr, mask)

    display_network_info(network)

    if prefixlength:

        if re.match(REGEX_NETMASK_DOTTED_DECIMAL, prefixlength):
            prefixlength = dotted_decimal_to_cidr(prefixlength)
        if re.match(REGEX_NETMASK_DOTTED_DECIMAL, mask):
            mask = dotted_decimal_to_cidr(mask)

        if prefixlength and int(mask) == int(prefixlength):
            sys.exit(f"error: network overlap: subnet is the same length as supernet")

        elif prefixlength and int(mask) > int(prefixlength):
            display_supernet_info(network, prefixlength)
        elif prefixlength and int(mask) < int(prefixlength):
            display_subnet_info(network, prefixlength)

    sys.exit(0)

if __name__ == "__main__":
    main()