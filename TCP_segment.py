import struct


class TCPSeg:
    def __init__(self):
        pass

    def tcp_segment(self, data):
        (src_port, dest_port, seq, ack, offset_reserved_flags) = struct.unpack(
            '! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12)*4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rsh = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1

        return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rsh, flag_syn, flag_fin, data[offset:]

    def display_tcp(self, data):
        (src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh,
         flag_rsh, flag_syn, flag_fin, data) = self.tcp_segment(data)
        print("TCP")
        print(f"Source: {src_port}, Destination: {dest_port}")
        print(f"Sequence: {seq}, Acknowledgment: {ack}")
        print("Flags: ")
        print(
            f"URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh} \nRST: {flag_rsh}, SYN: {flag_syn}, FIN: {flag_fin}")
        print(f"Data: {data}")
