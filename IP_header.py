import struct

'''
IP header
version -> header length -> type of service
ID -> fragment offset
ttl -> protocol -> checksum
src address
destination address
'''
class IPHeader:
    def __init__(self):
        pass
    # unpacking the IPv4 packet
    def ipv4_packet(self, data):
        # the version can be extracted from the version header length
        # by using bit wise operation
        version_header_length = data[0]
        # by shifting to the right 4 bits, the header length will be removed
        # and the version will only be left
        version = version_header_length >> 4
        # you need the header length, cause that is what is going to be used to determine where the data starts
        header_len = (version_header_length & 15) * 4
        # ! is there to make sure the order is correct
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_len, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_len:]

    # return properly formatted IPv4 address
    def ipv4(self, addr):
        return '.'.join(map(str, addr))