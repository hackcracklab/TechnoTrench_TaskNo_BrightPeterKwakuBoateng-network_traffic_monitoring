import socket
from struct import *
import time
# Helper functions
def get_mac_addr(addr):
    return ':'.join('%02x' % b for b in addr)

def get_ip(addr):
    return '.'.join(map(str, addr))

def format_multi_line(prefix, string):
    """Format multi-line output for TCP data."""
    # Decode bytes to string if necessary
    if isinstance(string, bytes):
        string = string.decode(errors='ignore')  # Decode bytes to string
    return '\n'.join(prefix + line for line in string.splitlines())

# Header parsing functions
def ethernet_head(raw_data):
    dest, src, proto = unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(proto)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src)
    target = get_ip(target)
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data

def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

# Main function
def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
        if eth[2] == 8:
            ipv4 = ipv4_head(eth[3])
            print('\t - IPv4 Packet:')
            print('\t\t - Version: {}, Header Length: {}, TTL: {}'.format(ipv4[0], ipv4[1], ipv4[2]))
            print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], ipv4[4], ipv4[5]))
            if ipv4[3] == 6:
                tcp = tcp_head(ipv4[6])
                print('\t\t - TCP Segment:')
                print('\t\t\t - Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('\t\t\t - Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                print('\t\t\t - Flags:')
                print('\t\t\t\t - URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
                print('\t\t\t\t - RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))
                if len(tcp[10]) > 0:
                    print('\t\t\t - TCP Data:')
                    print(format_multi_line('\t\t\t\t', tcp[10]))

if __name__ == '__main__':
    main()
