import struct


class ICMPSeg:
    def __init__(self):
        pass

    def icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def display_icmp(self, data):
        icmp_type, code, checksum, data = self.icmp_packet(data)
        print("ICMP Packet: ")
        print(f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
        print(f"Data: {data} ")
