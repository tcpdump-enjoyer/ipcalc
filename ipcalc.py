#!/usr/bin/python3

import argparse
import re
import sys

# matches: 192.168.1.1 or 192.168.1.1/24 or 192.168.1.0/255.255.255.0
# group 1: 192.168.1.1
# group 2: 24 or 255.255.255.0
REGEX_IPADDR = "^((?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}))(?:\/((?:3[0-2]|[12]\d|\d)|(?:(?:(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})))))?$"

# matches: 24 or 255.255.255.0
REGEX_SUBNET = "^((?:3[0-2]|[12]\d|\d)|(?:(?:(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}))))$"

REGEX_NETMASK_CIDR = "^(?:3[0-2]|[12]\d|\d)$"
REGEX_NETMASK_DOTTED_DECIMAL = "^(?:(?:(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})))$"
                               
def dotted_decimal_to_binary(address: str) -> str:
    """
    Returns the binary representation from an IP address or subnet mask in dotted decimal notation.
    """
    result = ""
    for byte in address.split("."):
        result += bin(int(byte))[2:].rjust(8, "0") # remove '0b' and stuff with '0' for a full 8-bit representation
    return result

def binary_to_dotted_decimal(bitstring: str) -> str:
    """
    Returns the dotted decimal notation of an IP address or subnet mask from its 32-bit string representation.
    """
    bytes = [bitstring[i:i+8] for i in range(0, len(bitstring), 8)]
    return ".".join([str(int(byte, 2)) for byte in bytes])

def cidr_to_dotted_decimal(subnet_mask: str) -> str:
    """
    Returns the dotted decimal notation of a subnet mask from its CIDR notation.
    """
    bitstring = "1" * int(subnet_mask)
    bitstring += "0" * (32 - int(subnet_mask))
    byte_array = [bitstring[i:i+8] for i in range(0, len(bitstring), 8)]
    result = [str(int(byte, 2)) for byte in byte_array]
    result = ".".join(result)
    return result

def dotted_decimal_to_cidr(subnet_mask: str) -> str:
    """
    Returns the CIDR notation of a subnet mask from its dotted decimal notation.
    """
    return str(dotted_decimal_to_binary(subnet_mask).count("1"))

def wildcard(mask: str, binary: bool = False) -> str:
    """
    Returns the inverted mask from bit string `mask`.\n
    Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.
    """
    result = "".join(["0" if bit == "1" else "1" for bit in mask])
    return result if binary else binary_to_dotted_decimal(result)

def network_address(address: str, subnet_mask: str, binary: bool = False) -> str:
    """
    Returns the network address given `address` and `subnet_mask` in dotted decimal notation.\n
    Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.
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
    Returns the broadcast address given `address` and `subnet_mask` in dotted decimal notation.\n
    Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.
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
    Returns the first address of the given network.\n
    Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.
    """
    result = network_address(address, subnet_mask, binary=True)[:-1] + "1"
    return result if binary else binary_to_dotted_decimal(result)

def network_max(address: str, subnet_mask: str, binary: bool = False) -> str:
    """
    Returns the last address of the given network.\n
    Set binary to `True` to output result as a bit string instead of using the dotted decimal notation.
    """
    result = network_broadcast(address, subnet_mask, binary=True)[:-1] + "0"
    return result if binary else binary_to_dotted_decimal(result)

def network_hosts(cidr: str):
    return 2 ** ( 32 - int(cidr) ) - 2

class Network():
    def __init__(self, address: str, subnet_mask: str):
        """
        - address: dotted-decimal representation of an IPv4 address.
        - netmask: dotted-decimal or CIDR representation of an IPv4 network mask
        """

        self.address    = None
        self.mask       = None
        self.cidr       = None
        self.wildcard   = None
        self.min        = None
        self.max        = None
        self.broadcast  = None
        self.hosts      = None
        self.classful   = None
        self.private    = None
        self.usage      = None

        self.__set_mask(subnet_mask)
        self.__set_cidr(subnet_mask)
        self.__set_wildcard()
        self.__set_address(address)
        self.__set_broadcast()
        self.__set_min()
        self.__set_max()
        self.__set_hosts()
        self.__set_classful()
        self.__set_private()

    def __set_address(self, address):
        self.address = network_address(address, self.mask)
        
    def __set_mask(self, subnet_mask):
        if re.match(REGEX_NETMASK_DOTTED_DECIMAL, subnet_mask):
            self.mask = subnet_mask
        else:
            self.mask = cidr_to_dotted_decimal(subnet_mask)
        
    def __set_cidr(self, subnet_mask):
        if re.match(REGEX_NETMASK_CIDR, subnet_mask):
            self.cidr = subnet_mask
        else:
            self.cidr = dotted_decimal_to_cidr(subnet_mask)
        
    def __set_wildcard(self):
        self.wildcard = wildcard(dotted_decimal_to_binary(self.mask))
        
    def __set_broadcast(self):
        self.broadcast = network_broadcast(self.address, self.mask)
        
    def __set_min(self):
        self.min = network_min(self.address, self.mask)
        
    def __set_max(self):
        self.max = network_max(self.address, self.mask)
        
    def __set_hosts(self):
        self.hosts = network_hosts(self.cidr)
        
    def __set_classful(self):
        leading_bits = dotted_decimal_to_binary(self.address)
        if leading_bits.startswith("0"):
            self.classful = "A"
        elif leading_bits.startswith("10"):
            self.classful = "B"
        elif leading_bits.startswith("110"):
            self.classful = "C"
        elif leading_bits.startswith("1110"):
            self.classful = "D"
        elif leading_bits.startswith("1111"):
            self.classful = "E"
    
    def __set_private(self):
        if network_address(self.address, "255.0.0.0") == network_address("10.0.0.0", "255.0.0.0")\
        or network_address(self.address, "255.240.0.0") == network_address("172.16.0.0", "255.240.0.0")\
        or network_address(self.address, "255.255.0.0") == network_address("192.168.0.0", "255.255.0.0"):
            self.private = True
        else:
            self.private = False

    def __set_usage(self):
        ...
        
    def belongs_to(self, address: str, subnet_mask: str) -> bool:
        """
        Returns `True` if self is a subnet of the given network.\n
        FIXME: subnet_mask must be in dotted decimal notation
            because of network_address()
            but => dotted_decimal_to_cidr(subnet_mask)
        """
        print("self:", network_address(self.address, subnet_mask))
        print("othr:", network_address(address, subnet_mask))
        if network_address(self.address, subnet_mask) == network_address(address, subnet_mask)\
        and int(self.cidr) >= int(dotted_decimal_to_cidr(subnet_mask)):
            return True
        else:
            return False


class Zbob():
    def uwu(parametre_sympa: Network):
        parametre_sympa.mask

def main():

    addr = re.match(REGEX_IPADDR, args.network).group(1)
    mask = re.match(REGEX_IPADDR, args.network).group(2)
    subnet = re.match(REGEX_SUBNET, args.subnet)

    if not addr:
        sys.exit(f"error: invalid value: {args.network}")

    if not mask:
        mask = "24"

    network = Network(addr, mask) # default: 192.168.1.1/24

    print(network.__dict__)
    print("true", network.belongs_to("192.168.1.0", cidr_to_dotted_decimal("23")))
    print("true", network.belongs_to("192.168.1.0", cidr_to_dotted_decimal("24")))
    print("false", network.belongs_to("192.168.1.0", cidr_to_dotted_decimal("25")))

    # print(f"Address\t{...}\t{...}")
    # print(f"Netmask\t{...}\t{...}")
    # print(f"Wildcard\t{...}\t{...}")
    # print(f"Network\t{...}\t{...}")
    # print(f"Broadcast\t{...}\t{...}")
    # print(f"HostMin\t{...}\t{...}")
    # print(f"HostMax\t{...}\t{...}")
    # print(f"Hosts/Net\t{...}\t{...}")
    sys.exit(0)

if __name__ == "__main__":
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("network", nargs='?', type=str, default="192.168.1.1/24")
    parser.add_argument("subnet", nargs='?', type=str, default="")
    args = parser.parse_args()
    main()