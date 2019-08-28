#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range.")
    (options, arguments) = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for client in answered_list:
        client_dist = {"ip": client[1].psrc, "mac": client[1].hwsrc}
        clients_list.append(client_dist)
    return clients_list

def print_result(result_list):
    print("+--------------------------------------------+")
    print("| IP\t\t\tMAC\t\t     |")
    print("+--------------------------------------------+")
    for client in result_list:
        print("| "+client["ip"]+"\t\t"+client["mac"]+"    |")
    print("+--------------------------------------------+")

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)


