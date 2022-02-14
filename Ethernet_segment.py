import socket
import struct


class EthernetSeg:
    def __init__(self):
        pass
    
    # unpacking the ethernet frame
    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    # return a properly formatted MAC address
    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    # unpacking the IPv4 packet
    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        # you need the header length, cause that is what is going to be used to determine where the data starts
        header_len = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_len, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_len:]

    # return properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))
