# !/usr/bin/env python

# from optparse import OptionParser
from argparse import ArgumentParser
import scapy.all as scapy

def get_arguments():
    # parser = OptionParser()
    parser = ArgumentParser()
    # parser.add_option("-i", "--ip", dest="ip", help="Tarmoqni skaner qilish uchun IP manzilni kiriting.", metavar="IP")
    parser.add_argument("-i", "--ip", dest="ip", help="Tarmoqni skaner qilish uchun IP manzilni kiriting.", metavar="Enter the target IP")
    options, _ = parser.parse_args()

    if not options.ip:
        parser.error("IP manzilni kiriting yoki '--help' yordamida yordamchi xabarni ko'ring.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.ip)
print_result(scan_result)
