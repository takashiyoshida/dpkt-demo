#!/usr/bin/env python3

from datetime import datetime
import socket

import dpkt
from dpkt.compat import compat_ord


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def main():
    with open('test.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            print('Timestamp: ', str(datetime.utcfromtimestamp(ts)))

            eth = dpkt.ethernet.Ethernet(buf)
            print('Ethernet frame: ', mac_addr(
                eth.src), mac_addr(eth.dst), eth.type)

            if not isinstance(eth.data, dpkt.ip.IP):
                print('Non-IP packet type not supported %s\n' %
                      eth.data.__class__.__name__)
                continue

            ip = eth.data
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            print('IP: %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % (inet_to_str(ip.src),
                                                                            inet_to_str(
                                                                                ip.dst),
                                                                            ip.len,
                                                                            ip.ttl,
                                                                            do_not_fragment,
                                                                            more_fragments,
                                                                            fragment_offset))


if __name__ == "__main__":
    main()
