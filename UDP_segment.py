import struct


class UDPSeg:
    def __init__(self):
        pass

    def udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def display_udp(self, data):
        src_port, dest_port, length, data = self.udp_segment(data)
        print("UDP")
        print(
            f'Source Port: {src_port}\nDestination Port: {dest_port}\nLength: {length}')
