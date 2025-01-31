#!/usr/bin/env python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
from scapy.all import sniff, rdpcap, wrpcap, Ether, Dot1Q, IP, VRRP, VRRPv3, STP, IPv6, AH, Dot3, ARP, TCP, UDP, CookedLinux
from scapy.contrib.macsec import MACsec, MACsecSCI
from scapy.contrib.eigrp import EIGRP, EIGRPAuthData
from scapy.contrib.ospf import OSPF_Hdr
from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPlatform, CDPMsgPortID, CDPAddrRecordIPv4, CDPMsgSoftwareVersion
from scapy.contrib.dtp import DTP
from scapy.layers.hsrp import HSRP, HSRPmd5
from scapy.layers.llmnr import LLMNRQuery
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
from scapy.layers.eap import EAPOL
from scapy.contrib.tacacs import TacacsHeader
from scapy.contrib.bgp import BGPHeader, BGPOpen
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import *
from scapy.layers.inet6 import ICMPv6ND_RS
from scapy.contrib.lldp import LLDPDU, LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUPortID, LLDPDUManagementAddress
from colorama import Fore, Style, init
import socket
import signal
import sys
import os

# For colors (colorama)
init(autoreset=True)

# Stocke les paquets déjà affichés
seen_packets = {
    "MACSec": set(),
    "OSPF": set(),
    "BGP": set(),
    "HSRP": set(),
    "VRRP": set(),
    "VRRPv3": set(),
    "GLBP": set(),
    "DTP": set(),
    "STP": set(),
    "CDP": set(),
    "EIGRP": set(),
    "LLMNR": set(),
    "NBT_NS": set(),
    "MDNS": set(),
    "EAPOL": set(),
    "DHCP": set(),
    "VLAN": set(),
    "IGMP": set(),
    "ICMPv6": set(),
    "LLDP": set(),
    "MNDP": set(),
    "DHCPv6": set(),
    "SSDP": set(),
    "ModbusTCP": set(),
    "OMRON": set(),
    "S7COMM": set(),
    "TACACS": set(),
    "RADIUS": set(),
    "SNMP": set(),
}

# pcap parsing, cold mode
def analyze_pcap(pcap_path, args):
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File not found: {pcap_path}")
        return

    packets = rdpcap(pcap_path)
    if not packets:
        print(f"[WARNING] No packets found in {pcap_path}")
        return

    for packet in packets:
        packet_detection(packet, args)

# Packet Processing
def packet_detection(packet, args):
    global seen_packets

    if args.MACSec and packet.haslayer(MACsec):

        try:
            packet_key_MACSec = str(packet[0][MACsec][MACsecSCI].system_identifier)
        except:
            packet_key_MACSec = "Unknown"

        if packet_key_MACSec in seen_packets["MACSec"]:
            return

        seen_packets["MACSec"].add(packet_key_MACSec)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MACSec")
        print(Fore.YELLOW + Style.BRIGHT + "[+] The network may be using 802.1X, keep that in mind")
        print(Fore.GREEN + Style.BRIGHT + "[*] System Identifier: " + Fore.WHITE + Style.BRIGHT + packet_key_MACSec)

    if args.OSPF and packet.haslayer(OSPF_Hdr):
        def hex_to_string(hex):
            if hex[:2] == '0x':
                hex = hex[2:]
            string_value = bytes.fromhex(hex).decode('utf-8')
            return string_value
        packet_key_OSPF = hex_to_string(hex(packet[OSPF_Hdr].area))

        if packet_key_OSPF in seen_packets["OSPF"]:
            return

        seen_packets["OSPF"].add(packet_key_OSPF)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected OSPF Packet")
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin, Routing Table Overflow")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Area ID: " + Fore.WHITE + Style.BRIGHT + str(packet[OSPF_Hdr].area))
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(packet[OSPF_Hdr].src))

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        if packet[OSPF_Hdr].authtype == 0x0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: No")
        elif packet[OSPF_Hdr].authtype == 0x1:
            raw = packet[OSPF_Hdr].authdata
            hex_value = hex(raw)
            string = hex_to_string(hex_value)
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: Plaintext Phrase: " + string)
        elif packet[OSPF_Hdr].authtype == 0x02:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: MD5 or SHA-256")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: Ettercap, John the Ripper")
            print(Fore.GREEN + Style.BRIGHT + "[*] OSPF Key ID: " + Fore.WHITE + Style.BRIGHT + str(packet[OSPF_Hdr].keyid))
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable passive interfaces, use authentication")

    if args.BGP and packet.haslayer(BGPHeader):
        bgp_header = packet.getlayer(BGPHeader)
        packet_key_BGP = str(bgp_header.fields)

        if packet_key_BGP in seen_packets["BGP"]:
            return

        seen_packets["BGP"].add(packet_key_BGP)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected BGP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Route Hijacking")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, FRRouting")

        if bgp_header:
            print(Fore.GREEN + Style.BRIGHT + "[*] BGP Header Fields: " + Fore.WHITE + Style.BRIGHT + str(bgp_header.fields))

        if packet.haslayer(BGPOpen):
            bgp_open = packet.getlayer(BGPOpen)
            print(Fore.GREEN + Style.BRIGHT + "[*] Source AS Number: " + Fore.WHITE + Style.BRIGHT + str(bgp_open.my_as))
            print(Fore.GREEN + Style.BRIGHT + "[*] Peer IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
            print(Fore.GREEN + Style.BRIGHT + "[*] Hold Time: " + Fore.WHITE + Style.BRIGHT + str(bgp_open.hold_time))

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] Peer MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use authentication, filter routes")

    if args.HSRP and packet.haslayer(HSRP) and packet[HSRP].state == 16:
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'
        packet_key_HSRP = str(mac_src)

        if packet_key_HSRP in seen_packets["HSRP"]:
            return

        seen_packets["HSRP"].add(packet_key_HSRP)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected HSRP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP active router priority: " + Fore.WHITE + Style.BRIGHT + str(packet[HSRP].priority))
        print(Fore.GREEN + Style.BRIGHT + "[+] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, Yersinia")
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Group Number: " + Fore.WHITE + Style.BRIGHT + str(packet[HSRP].group))
        print(Fore.GREEN + Style.BRIGHT + "[+] HSRP Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + str(packet[HSRP].virtualIP))
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] HSRP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        if packet.haslayer(HSRPmd5):
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "MD5")
            print(Fore.YELLOW + Style.BRIGHT + "[*] Tools for bruteforce: hsrp2john.py, John the Ripper")
        elif packet[HSRP].auth:
            hsrpv1_plaintext = packet[HSRP].auth
            simplehsrppass = hsrpv1_plaintext.decode("UTF-8")
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: " + Fore.WHITE + Style.BRIGHT + "Plaintext Phrase: " + simplehsrppass)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use priority 255, use authentication")

    if args.VRRP and packet.haslayer(VRRP):

        try:
            packet_key_VRRP = f"{packet[IP].src}-{packet[VRRP].vrid}"
        except:
            packet_key_VRRP = "Unknown"

        if packet_key_VRRP in seen_packets["VRRP"]:
            return

        seen_packets["VRRP"].add(packet_key_VRRP)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv2 Packet")

        if packet.haslayer(AH):
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: AH Header detected, VRRP packet is encrypted")
            return

        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 master router priority: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRP].priority))
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Group Number: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRP].vrid))

        if packet.haslayer(IP):
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))

        if packet[VRRP].addrlist:
            print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + ', '.join(packet[VRRP].addrlist))

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv2 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)

        auth_type = getattr(packet[VRRP], 'authtype', None)
        if auth_type == 0:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: No")
        elif auth_type == 0x1:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: Plaintext. Look at the password in Wireshark")
        elif auth_type == 254:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: MD5")

        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use authentication, filter VRRP traffic using ACL")

    if args.VRRPv3 and packet.haslayer(VRRPv3):
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        packet_key_VRRPv3 = str(mac_src)
        if packet_key_VRRPv3 in seen_packets["VRRPv3"]:
            return

        seen_packets["VRRPv3"].add(packet_key_VRRPv3)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected VRRPv3 Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 master router priority: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRPv3].priority))
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Loki")
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Group Number: " + Fore.WHITE + Style.BRIGHT + str(packet[VRRPv3].vrid))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.GREEN + Style.BRIGHT + "[*] VRRPv3 Virtual IP Address: " + Fore.WHITE + Style.BRIGHT + ', '.join(packet[VRRPv3].addrlist))
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Filter VRRP traffic using ACL")

    if args.GLBP and packet.haslayer(IP) and packet.haslayer(UDP):
        if packet[IP].dst == "224.0.0.102" and packet[UDP].dport == 3222:
            if packet.haslayer(Ether):
                mac_src = packet[Ether].src
            elif packet.haslayer(CookedLinux):
                mac_src = 'Unknown (Cooked Capture)'
            else:
                mac_src = 'Unknown'
            packet_key_GLBP = str(mac_src)

            if packet_key_GLBP in seen_packets["GLBP"]:
                return

            seen_packets["GLBP"].add(packet_key_GLBP)

            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected GLBP Packet")
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MITM")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki")
            print(Fore.YELLOW + Style.BRIGHT + "[!] GLBP has not yet been implemented by Scapy")
            print(Fore.YELLOW + Style.BRIGHT + "[!] Check AVG router priority values manually using Wireshark")
            print(Fore.YELLOW + Style.BRIGHT + "[!] If the AVG router's priority value is less than 255, you have a chance of launching a MITM attack.")
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Sender MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
            print(Fore.GREEN + Style.BRIGHT + "[*] GLBP Sender IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use priority 255, use authentication")

    if args.DTP and packet.haslayer(DTP):
        if packet.haslayer(Dot3):
            mac_src = packet[Dot3].src
        elif packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        packet_key_DTP = str(mac_src)

        if packet_key_DTP in seen_packets["DTP"]:
            return

        seen_packets["DTP"].add(packet_key_DTP)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected DTP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "VLAN Segmentation Bypass")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")
        print(Fore.GREEN + Style.BRIGHT + "[*] DTP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable DTP")

    if args.STP and packet.haslayer(STP):
        if packet.haslayer(Ether):
            root_switch_mac = str(packet[STP].rootmac)
        elif packet.haslayer(CookedLinux):
            root_switch_mac = 'Unknown (Cooked Capture)'
        else:
            root_switch_mac = 'Unknown'
        packet_key_STP = str(root_switch_mac)

        if packet_key_STP in seen_packets["STP"]:
            return

        seen_packets["STP"].add(packet_key_STP)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected STP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Partial MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Yersinia, Scapy")

        if packet.haslayer(Ether):
            root_switch_mac = str(packet[STP].rootmac)
        elif packet.haslayer(CookedLinux):
            root_switch_mac = 'Unknown (Cooked Capture)'
        else:
            root_switch_mac = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Switch MAC: " + Fore.WHITE + Style.BRIGHT + root_switch_mac)
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root ID: " + Fore.WHITE + Style.BRIGHT + str(packet[STP].rootid))
        print(Fore.GREEN + Style.BRIGHT + "[*] STP Root Path Cost: " + Fore.WHITE + Style.BRIGHT + str(packet[STP].pathcost))
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable BPDU Guard")

    if args.CDP and packet.haslayer(CDPv2_HDR):
        hostname = packet[CDPMsgDeviceID].val.decode() if packet.haslayer(CDPMsgDeviceID) else "Unknown"
        os_version = packet[CDPMsgSoftwareVersion].val.decode() if packet.haslayer(CDPMsgSoftwareVersion) else "Unknown"
        platform = packet[CDPMsgPlatform].val.decode() if packet.haslayer(CDPMsgPlatform) else "Unknown"
        port_id = packet[CDPMsgPortID].iface.decode() if packet.haslayer(CDPMsgPortID) else "Unknown"
        ip_address = packet[CDPAddrRecordIPv4].addr if packet.haslayer(CDPAddrRecordIPv4) else "Not Found"
        mac = packet[Ether].src if packet.haslayer(Ether) else packet[Dot3].src if packet.haslayer(Dot3) else 'Unknown (Cooked Capture)' if packet.haslayer(CookedLinux) else 'Unknown'
        
        packet_key_CDP = (hostname, os_version, platform, port_id, ip_address, mac)

        if packet_key_CDP in seen_packets["CDP"]:
            return
        seen_packets["CDP"].add(packet_key_CDP)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected CDP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering, CDP Flood")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Wireshark, Yersinia")
        print(Fore.GREEN + Style.BRIGHT + "[*] Platform: " + Fore.WHITE + Style.BRIGHT + platform)
        print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + ip_address)
        print(Fore.GREEN + Style.BRIGHT + "[*] Mac: " + Fore.WHITE + Style.BRIGHT + mac)
        print(Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + hostname)
        print(Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + os_version)
        print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + port_id)

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] CDP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable CDP if not required, be careful with VoIP")

    if args.EIGRP and packet.haslayer(EIGRP):

        try:
            as_number = str(packet[EIGRP].asn)
            if packet.haslayer(IP):
                neighbor_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                neighbor_ip = packet[IPv6].src
            else:
                neighbor_ip = "Unknown"

            packet_key_EIGRP = f"{neighbor_ip}-{as_number}"
        except:
            packet_key_EIGRP = "Unknown"

        if packet_key_EIGRP in seen_packets["EIGRP"]:
            return

        seen_packets["EIGRP"].add(packet_key_EIGRP)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected EIGRP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Subnets Discovery, Blackhole, Evil Twin")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Loki, Scapy, FRRouting")
        print(Fore.GREEN + Style.BRIGHT + "[*] AS Number: " + Fore.WHITE + Style.BRIGHT + as_number)

        if packet.haslayer(IP):
            print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        elif packet.haslayer(IPv6):
            print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IPv6].src))

        if packet.haslayer(Ether):
            neighbor_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            neighbor_mac = 'Unknown (Cooked Capture)'
        else:
            neighbor_mac = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] EIGRP Neighbor MAC: " + Fore.WHITE + Style.BRIGHT + neighbor_mac)

        if packet.haslayer(EIGRPAuthData):
            print(Fore.YELLOW + Style.BRIGHT + "[!] There is EIGRP Authentication")
            authtype = packet[EIGRPAuthData].authtype
            if authtype == 2:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: MD5")
                print(Fore.GREEN + Style.BRIGHT + "[*] Tools for bruteforce: eigrp2john.py, John the Ripper")
            elif authtype == 3:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: SHA-256")
        else:
            print(Fore.YELLOW + Style.BRIGHT + "[!] Authentication: No")

        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable passive interfaces, use authentication")

    if args.LLMNR and packet.haslayer(UDP) and packet[UDP].dport == 5355:
        try:
            llmnr_query_name = packet[LLMNRQuery].qd.qname.decode()
        except:
            llmnr_query_name = "Not Found"

        packet_key_LLMNR = str(llmnr_query_name)

        if packet_key_LLMNR in seen_packets["LLMNR"]:
            return

        seen_packets["LLMNR"].add(packet_key_LLMNR)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLMNR Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "LLMNR Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Query Name: " + Fore.WHITE + Style.BRIGHT + llmnr_query_name)

        try:
            llmnr_trans_id = packet[LLMNRQuery].id
        except:
            llmnr_trans_id = "Not Found"
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + str(llmnr_trans_id))

        if packet.haslayer(IP):
            ip_src = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
        else:
            print(Fore.RED + Style.BRIGHT + "[!] No IP layer found")
            return

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker IP: " + Fore.WHITE + Style.BRIGHT + ip_src)
        print(Fore.GREEN + Style.BRIGHT + "[*] LLMNR Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLMNR")

    if args.NBT_NS and packet.haslayer(UDP) and packet[UDP].dport == 137:

        try:
            question_name = packet[0]["NBNS registration request"].QUESTION_NAME.decode()
        except:
            question_name = "Unknown"

        try:
            transaction_id = str(packet[0]["NBNS Header"].NAME_TRN_ID)
        except:
            transaction_id = "Unknown"

        try:
            speaker_ip = str(packet[0][IP].src)
        except:
            speaker_ip = "Unknown"

        packet_key_NBT_NS = f"{speaker_ip}-{transaction_id}-{question_name}"

        if packet_key_NBT_NS in seen_packets["NBT_NS"]:
            return

        seen_packets["NBT_NS"].add(packet_key_NBT_NS)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected NBT-NS Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "NBT-NS Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Question Name: " + Fore.WHITE + Style.BRIGHT + question_name)
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Packet Transaction ID: " + Fore.WHITE + Style.BRIGHT + transaction_id)
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker IP: " + Fore.WHITE + Style.BRIGHT + speaker_ip)

        if packet.haslayer(Ether):
            speaker_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            speaker_mac = 'Unknown (Cooked Capture)'
        else:
            speaker_mac = 'Unknown'
        
        print(Fore.GREEN + Style.BRIGHT + "[*] NBT-NS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + speaker_mac)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable NBT-NS")

    if args.MDNS and packet.haslayer(UDP) and packet[UDP].dport == 5353:

        if packet.haslayer(IP):
            ip_src = packet[IP].src
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src

        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
        else:
            mac_src = 'Unknown'

        packet_key_MDNS = str(mac_src)

        if packet_key_MDNS in seen_packets["MDNS"]:
            return

        seen_packets["MDNS"].add(packet_key_MDNS)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MDNS Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "MDNS Spoofing, Credentials Interception")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Responder")
        print(Fore.YELLOW + Style.BRIGHT + "[*] MDNS Spoofing works specifically against Windows machines")
        print(Fore.YELLOW + Style.BRIGHT + "[*] You cannot get NetNTLMv2-SSP from Apple devices")
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(ip_src))
        print(Fore.GREEN + Style.BRIGHT + "[*] MDNS Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT +  "Filter MDNS traffic. Be careful with MDNS filtering")

    if args.EAPOL and packet.haslayer(EAPOL):

        try:
            version = str(packet[EAPOL].version)
        except:
            version = "Unknown"

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = 'Unknown'

        packet_key_EAPOL = f"{source_mac}-{version}"

        if packet_key_EAPOL in seen_packets["EAPOL"]:
            return

        seen_packets["EAPOL"].add(packet_key_EAPOL)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected EAPOL")

        if version == "3":
            print(Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: 2010")
        elif version == "2":
            print(Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: 2004")
        elif version == "1":
            print(Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: 2001")
        else:
            print(Fore.YELLOW + Style.BRIGHT + "[*] 802.1X Version: Unknown")

    if args.DHCP and packet.haslayer(UDP) and packet[UDP].dport == 67 and packet.haslayer(DHCP):
        dhcp_options = packet[DHCP].options

        packet_key_DHCP = tuple(dhcp_options)

        if packet_key_DHCP in seen_packets["DHCP"]:
            return

        seen_packets["DHCP"].add(packet_key_DHCP)
        for option in dhcp_options:
            if option[0] == 'message-type' and option[1] == 1:
                print(Fore.WHITE + Style.BRIGHT + '-' * 50)
                print(Fore.WHITE + Style.BRIGHT + "[+] Detected DHCP Discovery")
                print(Fore.YELLOW + Style.BRIGHT + "[*] DHCP Discovery can lead to unauthorized network configuration")
                print(Fore.GREEN + Style.BRIGHT + "[*] DHCP Client IP: " + Fore.WHITE + Style.BRIGHT + "0.0.0.0 (Broadcast)")

                if packet.haslayer(Ether):
                    mac_src = packet[Ether].src
                elif packet.haslayer(CookedLinux):
                    mac_src = 'Unknown (Cooked Capture)'
                else:
                    mac_src = 'Unknown'
                print(Fore.GREEN + Style.BRIGHT + "[*] DHCP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
                print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use DHCP Snooping")

    if args.VLAN and packet.haslayer(Dot1Q):
        vlan_ids = set()
        vlan_ids.add(packet[Dot1Q].vlan)
        if len(vlan_ids) == 0:
            return
        vlan_id_string = ', '.join(Fore.WHITE + Style.BRIGHT + str(vlan_id) + Style.RESET_ALL for vlan_id in vlan_ids)
        packet_key_VLAN = frozenset(vlan_ids)

        if packet_key_VLAN in seen_packets["VLAN"]:
            return

        seen_packets["VLAN"].add(packet_key_VLAN)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected 802.1Q Tag")
        print(Fore.GREEN + Style.BRIGHT + "[!] Found VLAN IDs: " + Style.RESET_ALL + vlan_id_string)
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "VLAN Segmentation Bypass")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Native Linux tools")
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Carefully check the configuration of trunk ports")

    if args.IGMP and packet.haslayer(IGMP):
        igmp_type = packet[IGMP].type
        igmp_types = {
            0x11: "Membership Query", 0x12: "Version 1 - Membership Report",
            0x16: "Version 2 - Membership Report", 0x17: "Leave Group", 0x22: "Version 3 - Membership Report"
        }
        packet_key_IGMP = (igmp_type)

        if packet_key_IGMP in seen_packets["IGMP"]:
            return

        seen_packets["IGMP"].add(packet_key_IGMP)
        igmp_type_description = igmp_types.get(igmp_type, "Unknown IGMP Type")
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + f"[+] Detected IGMP Packet: {igmp_type_description}")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "IGMP Sniffing, IGMP Flood")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy, Wireshark")
        print(Fore.YELLOW + Style.BRIGHT + "[*] IGMP is used to manage multicast groups")
        print(Fore.YELLOW + Style.BRIGHT + "[*] IGMP types include queries, reports, and leaves")
        print(Fore.GREEN + Style.BRIGHT + "[*] IGMP Speaker IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        print(Fore.GREEN + Style.BRIGHT + "[*] Multicast Address: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].dst))
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "If there is a lot of multicast traffic, use IGMP Snooping")

    if args.ICMPv6 and packet.haslayer(ICMPv6ND_RS):

        try:
            source_ip = str(packet[IPv6].src)
        except:
            source_ip = "Unknown"

        packet_key_ICMPv6_RS = source_ip

        if packet_key_ICMPv6_RS in seen_packets["ICMPv6_RS"]:
            return

        seen_packets["ICMPv6_RS"].add(packet_key_ICMPv6_RS)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected ICMPv6 Router Solicitation (RS)")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Potential for DoS attacks and network reconnaissance")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Scapy")
        print(Fore.YELLOW + Style.BRIGHT + "[*] ICMPv6 RS messages are used by devices to locate routers")
        print(Fore.GREEN + Style.BRIGHT + "[*] IPv6 Source Address: " + Fore.WHITE + Style.BRIGHT + source_ip)
        print(Fore.GREEN + Style.BRIGHT + "[*] Target of Solicitation: " + Fore.WHITE + Style.BRIGHT + "All Routers Multicast Address (typically ff02::2)")

    if args.LLDP and packet.haslayer(LLDPDU):
        hostname = packet[LLDPDUSystemName].system_name.decode() if packet.haslayer(LLDPDUSystemName) and isinstance(packet[LLDPDUSystemName].system_name, bytes) else packet[LLDPDUSystemName].system_name if packet.haslayer(LLDPDUSystemName) else "Not Found"
        os_version = packet[LLDPDUSystemDescription].description.decode() if packet.haslayer(LLDPDUSystemDescription) and isinstance(packet[LLDPDUSystemDescription].description, bytes) else packet[LLDPDUSystemDescription].description if packet.haslayer(LLDPDUSystemDescription) else "Not Found"
        port_id = packet[LLDPDUPortID].id.decode() if packet.haslayer(LLDPDUPortID) and isinstance(packet[LLDPDUPortID].id, bytes) else packet[LLDPDUPortID].id if packet.haslayer(LLDPDUPortID) else "Not Found"
        
        packet_key_LLDP = (hostname, os_version, port_id)

        if packet_key_LLDP in seen_packets["LLDP"]:
            return

        seen_packets["LLDP"].add(packet_key_LLDP)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected LLDP Frame")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Wireshark")
        print(Fore.GREEN + Style.BRIGHT + "[*] Hostname: " + Fore.WHITE + Style.BRIGHT + hostname)
        print(Fore.GREEN + Style.BRIGHT + "[*] OS Version: " + Fore.WHITE + Style.BRIGHT + os_version)
        print(Fore.GREEN + Style.BRIGHT + "[*] Port ID: " + Fore.WHITE + Style.BRIGHT + port_id)

        try:
            lldp_mgmt_address_bytes = packet[LLDPDUManagementAddress].management_address
            decoded_mgmt_address = socket.inet_ntoa(lldp_mgmt_address_bytes)
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + decoded_mgmt_address)
        except:
            print(Fore.GREEN + Style.BRIGHT + "[*] IP Address: " + Fore.WHITE + Style.BRIGHT + "Not Found")

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] LLDP Source MAC: " + Fore.WHITE + Style.BRIGHT + source_mac)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable LLDP if not required, be careful with VoIP")

    if args.MNDP and packet.haslayer(UDP) and packet[UDP].dport == 5678:
        if packet.haslayer(IP):
            speaker_ip = str(packet[IP].src)
        elif packet.haslayer(IPv6):
            speaker_ip = str(packet[IPv6].src)
        else:
            speaker_ip = "Unknown"
        packet_key_MNDP = (speaker_ip)

        if packet_key_MNDP in seen_packets["MNDP"]:
            return

        seen_packets["MNDP"].add(packet_key_MNDP)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected MNDP Packet")
        print(Fore.WHITE + Style.BRIGHT + "[*] MikroTik device may have been detected")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "Wireshark")
        print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker IP: " + Fore.WHITE + Style.BRIGHT + speaker_ip)

        if packet.haslayer(Ether):
            speaker_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            speaker_mac = 'Unknown (Cooked Capture)'
        else:
            speaker_mac = 'Unknown'

        print(Fore.GREEN + Style.BRIGHT + "[*] MNDP Speaker MAC: " + Fore.WHITE + Style.BRIGHT + speaker_mac)
        print(Fore.YELLOW + Style.BRIGHT + "[*] You can get more information from the packet in Wireshark")
        print(Fore.YELLOW + Style.BRIGHT + "[*] The MNDP protocol is not yet implemented in Scapy")
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Disable MNDP if not required")

    if args.DHCPv6 and packet.haslayer(UDP) and (packet[UDP].sport == 546 or packet[UDP].dport == 546 or packet[UDP].sport == 547 or packet[UDP].dport == 547):
        if packet.haslayer(Ether):
            mac_src = packet[Ether].src
            ip_src = packet[IPv6].src
        elif packet.haslayer(CookedLinux):
            mac_src = 'Unknown (Cooked Capture)'
            ip_src = packet[IPv6].src
        else:
            mac_src = 'Unknown'
            ip_src = 'Unknown'

        packet_key_DHCPv6 = str(mac_src)

        if packet_key_DHCPv6 in seen_packets["DHCPv6"]:
            return

        seen_packets["DHCPv6"].add(packet_key_DHCPv6)        

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected DHCPv6 Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Potential DNS IPv6 Spoofing")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "mitm6")
        print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.GREEN + Style.BRIGHT + "[*] DHCPv6 Speaker IP: " + Fore.WHITE + Style.BRIGHT + ip_src)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Enable RA Guard, SAVI")

    if args.SSDP and packet.haslayer(UDP) and packet[UDP].dport == 1900:
        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = 'Unknown'
        
        packet_key_SSDP = (source_mac)

        if packet_key_SSDP in seen_packets["SSDP"]:
            return

        seen_packets["SSDP"].add(packet_key_SSDP)  

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected SSDP Packet")
        print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Potential for UPnP Device Exploitation, MITM")
        print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "evil-ssdp")
        print(Fore.YELLOW + Style.BRIGHT + "[*] Not every SSDP packet tells you that an attack is possible")

        if packet.haslayer(IP):
            print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Source IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IP].src))
        elif packet.haslayer(IPv6):
            print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Source IP: " + Fore.WHITE + Style.BRIGHT + str(packet[IPv6].src))

        print(Fore.GREEN + Style.BRIGHT + "[*] SSDP Source MAC: " + Fore.WHITE + Style.BRIGHT + source_mac)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: "+ Fore.WHITE + Style.BRIGHT +  "Ensure UPnP is disabled on all devices unless absolutely necessary, monitor UPnP and SSDP traffic")

    if args.ModbusTCP and (packet.haslayer(ModbusADURequest) or packet.haslayer(ModbusADUResponse)):

        if packet.haslayer(ModbusADURequest):
            modbus_layer = packet[ModbusADURequest]
            packet_type = "Request"
        else:
            modbus_layer = packet[ModbusADUResponse]
            packet_type = "Response"

        try:
            transaction_id = str(modbus_layer.transId)
            proto_id = str(modbus_layer.protoId)
            unit_id = str(modbus_layer.unitId)
        except:
            transaction_id = "Unknown"
            proto_id = "Unknown"
            unit_id = "Unknown"

        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
        else:
            source_ip = "Unknown"
            dest_ip = "Unknown"

        packet_key_ModbusTCP = f"{source_ip}-{transaction_id}-{proto_id}-{unit_id}-{packet_type}"

        if packet_key_ModbusTCP in seen_packets["ModbusTCP"]:
            return

        seen_packets["ModbusTCP"].add(packet_key_ModbusTCP)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + f"[+] Detected Modbus ADU {packet_type} Packet")
        print(Fore.YELLOW + Style.BRIGHT + "[!] SCADA device may have been detected")
        print(Fore.GREEN + Style.BRIGHT + "[*] Transaction ID: " + Fore.WHITE + Style.BRIGHT + transaction_id)
        print(Fore.GREEN + Style.BRIGHT + "[*] Protocol ID: " + Fore.WHITE + Style.BRIGHT + proto_id)
        print(Fore.GREEN + Style.BRIGHT + "[*] Unit ID: " + Fore.WHITE + Style.BRIGHT + unit_id)

        if packet.haslayer(Ether):
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source MAC: " + Fore.WHITE + Style.BRIGHT + packet[Ether].src)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination MAC: " + Fore.WHITE + Style.BRIGHT + packet[Ether].dst)
        if packet.haslayer(IP):
            print(Fore.YELLOW + Style.BRIGHT + "[+] Source IP: " + Fore.WHITE + Style.BRIGHT + source_ip)
            print(Fore.YELLOW + Style.BRIGHT + "[+] Destination IP: " + Fore.WHITE + Style.BRIGHT + dest_ip)
        if packet.haslayer(TCP):
            print(Fore.WHITE + Style.BRIGHT + "[+] Source TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].sport))
            print(Fore.WHITE + Style.BRIGHT + "[+] Destination TCP Port: " + Fore.WHITE + Style.BRIGHT + str(packet[TCP].dport))

    if args.OMRON and packet.haslayer(UDP) and packet[UDP].dport == 9600:

        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
        else:
            source_ip = "Unknown"
            dest_ip = "Unknown"

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
            dest_mac = packet[Ether].dst
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
            dest_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = "Unknown"
            dest_mac = "Unknown"

        source_port = str(packet[UDP].sport) if packet.haslayer(UDP) else "Unknown"
        dest_port = str(packet[UDP].dport) if packet.haslayer(UDP) else "Unknown"

        packet_key_OMRON = f"{source_ip}-{source_mac}-{source_port}"

        if packet_key_OMRON in seen_packets["OMRON"]:
            return

        seen_packets["OMRON"].add(packet_key_OMRON)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Possible OMRON packet detection")
        print(Fore.YELLOW + Style.BRIGHT + "[!] SCADA device may have been detected")
        print(Fore.YELLOW + Style.BRIGHT + "[+] Source MAC: " + Fore.WHITE + Style.BRIGHT + source_mac)
        print(Fore.YELLOW + Style.BRIGHT + "[+] Destination MAC: " + Fore.WHITE + Style.BRIGHT + dest_mac)
        print(Fore.YELLOW + Style.BRIGHT + "[+] Source IP: " + Fore.WHITE + Style.BRIGHT + source_ip)
        print(Fore.YELLOW + Style.BRIGHT + "[+] Destination IP: " + Fore.WHITE + Style.BRIGHT + dest_ip)
        print(Fore.WHITE + Style.BRIGHT + "[+] Source UDP Port: " + Fore.WHITE + Style.BRIGHT + source_port)
        print(Fore.WHITE + Style.BRIGHT + "[+] Destination UDP Port: " + Fore.WHITE + Style.BRIGHT + dest_port)

    if args.S7COMM and packet.haslayer(TCP) and packet[TCP].dport == 102:

        if packet.haslayer(IP):
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
        else:
            source_ip = "Unknown"
            dest_ip = "Unknown"

        if packet.haslayer(Ether):
            source_mac = packet[Ether].src
            dest_mac = packet[Ether].dst
        elif packet.haslayer(CookedLinux):
            source_mac = 'Unknown (Cooked Capture)'
            dest_mac = 'Unknown (Cooked Capture)'
        else:
            source_mac = "Unknown"
            dest_mac = "Unknown"

        source_port = str(packet[TCP].sport) if packet.haslayer(TCP) else "Unknown"
        dest_port = str(packet[TCP].dport) if packet.haslayer(TCP) else "Unknown"

        packet_key_S7COMM = f"{source_ip}-{source_mac}-{source_port}"

        if packet_key_S7COMM in seen_packets["S7COMM"]:
            return

        seen_packets["S7COMM"].add(packet_key_S7COMM)

        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Possible S7COMM packet detection")
        print(Fore.YELLOW + Style.BRIGHT + "[!] SCADA device may have been detected")
        print(Fore.YELLOW + Style.BRIGHT + "[+] Source MAC: " + Fore.WHITE + Style.BRIGHT + source_mac)
        print(Fore.YELLOW + Style.BRIGHT + "[+] Destination MAC: " + Fore.WHITE + Style.BRIGHT + dest_mac)
        print(Fore.YELLOW + Style.BRIGHT + "[+] Source IP: " + Fore.WHITE + Style.BRIGHT + source_ip)
        print(Fore.YELLOW + Style.BRIGHT + "[+] Destination IP: " + Fore.WHITE + Style.BRIGHT + dest_ip)
        print(Fore.WHITE + Style.BRIGHT + "[+] Source TCP Port: " + Fore.WHITE + Style.BRIGHT + source_port)
        print(Fore.WHITE + Style.BRIGHT + "[+] Destination TCP Port: " + Fore.WHITE + Style.BRIGHT + dest_port)

    if args.TACACS and packet.haslayer(TacacsHeader):
        header = packet[TacacsHeader]
        packet_key_TACACS = str(header)

        if packet_key_TACACS in seen_packets["TACACS"]:
            return

        seen_packets["TACACS"].add(packet_key_TACACS)
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + "[+] Detected TACACS+ Packet")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS+ Type: " + Fore.WHITE + Style.BRIGHT + f"{header.type}")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS+ Flags: " + Fore.WHITE + Style.BRIGHT + f"{header.flags}")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS+ Session ID: " + Fore.WHITE + Style.BRIGHT + f"{header.session_id}")
        print(Fore.GREEN + Style.BRIGHT + "[+] TACACS+ Length: " + Fore.WHITE + Style.BRIGHT + f"{header.length}")

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(Fore.GREEN + Style.BRIGHT + "[*] Source IP: " + Fore.WHITE + Style.BRIGHT + f"{src_ip}")
            print(Fore.GREEN + Style.BRIGHT + "[*] Destination IP: " + Fore.WHITE + Style.BRIGHT + f"{dst_ip}")

        mac_src = packet.getlayer(Ether).src if packet.haslayer(Ether) else 'Unknown'
        print(Fore.GREEN + Style.BRIGHT + "[*] Source MAC: " + Fore.WHITE + Style.BRIGHT + mac_src)
        print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Use strong passwords, monitor unusual activities")

    if args.RADIUS and packet.haslayer(UDP) and packet[UDP].dport in [1812, 1813, 1645, 1646]:
        try:

            source_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src if packet.haslayer(IPv6) else "Unknown"
            dest_ip = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst if packet.haslayer(IPv6) else "Unknown"

            source_mac = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
            dest_mac = packet[Ether].dst if packet.haslayer(Ether) else "Unknown"

            source_port = str(packet[UDP].sport) if packet.haslayer(UDP) else "Unknown"
            dest_port = str(packet[UDP].dport) if packet.haslayer(UDP) else "Unknown"

            if not packet.haslayer(Radius):
                print(Fore.YELLOW + "[!] Warning: Packet on RADIUS port but no RADIUS layer detected")
                return

            radius_layer = packet[Radius]
            radius_code = getattr(radius_layer, "code", "Unknown")
            radius_id = getattr(radius_layer, "id", "Unknown")
            authenticator = getattr(radius_layer, "authenticator", None)

            packet_key_RADIUS = f"{source_ip}-{source_mac}-{source_port}-{radius_code}-{radius_id}"
            if packet_key_RADIUS in seen_packets["RADIUS"]:
                return

            seen_packets["RADIUS"].add(packet_key_RADIUS)

            radius_codes = {
                1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request",
                5: "Accounting-Response", 11: "Access-Challenge", 26: "NAS-Reboot-Request", 27: "NAS-Reboot-Response",
                40: "Disconnect-Request", 41: "Disconnect-ACK", 42: "Disconnect-NAK", 43: "CoA-Request",
                44: "CoA-ACK", 45: "CoA-NAK", 50: "IP-Address-Allocate", 51: "IP-Address-Release"
            }
            radius_code_desc = radius_codes.get(radius_code, "Unknown Code")

            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected RADIUS Packet")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Source IP: {Fore.WHITE + source_ip}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Destination IP: {Fore.WHITE + dest_ip}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Source MAC: {Fore.WHITE + source_mac}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Destination MAC: {Fore.WHITE + dest_mac}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Source Port: {Fore.WHITE + source_port}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Destination Port: {Fore.WHITE + dest_port}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] RADIUS Code: {Fore.WHITE + str(radius_code)} ({radius_code_desc})")
            print(Fore.GREEN + Style.BRIGHT + f"[*] RADIUS Identifier: {Fore.WHITE + str(radius_id)}")

            if authenticator:
                print(Fore.GREEN + Style.BRIGHT + f"[*] RADIUS Authenticator: {Fore.WHITE + authenticator.hex()}")
            else:
                print(Fore.YELLOW + Style.BRIGHT + "[!] No Authenticator found")

            for attr in getattr(radius_layer, "iterpayloads", lambda: [])():
                attr_name = getattr(attr, 'name', f"Attribute {getattr(attr, 'type', 'Unknown')}")
                attr_value = attr.fields.get("value", "Not Found")
                print(Fore.GREEN + Style.BRIGHT + f"[*] {attr_name}: {Fore.WHITE + str(attr_value)}")

            if packet.haslayer(RadiusAttr_User_Password):
                encrypted_password = packet[RadiusAttr_User_Password].value
                print(Fore.YELLOW + Style.BRIGHT + "[!] User Password (encrypted): " + Fore.WHITE + encrypted_password.hex())
            else:
                print(Fore.YELLOW + Style.BRIGHT + "[!] User Password: Not Present")

            if packet.haslayer(RadiusAttr_Vendor_Specific):
                vendor_id = packet[RadiusAttr_Vendor_Specific].vendor_id
                vendor_map = {311: "Microsoft", 9: "Cisco", 11: "Hewlett-Packard", 18: "Merit", 14179: "Juniper"}
                vendor_name = vendor_map.get(vendor_id, f"Unknown Vendor (ID: {vendor_id})")
                vendor_data = packet[RadiusAttr_Vendor_Specific].value

                print(Fore.GREEN + Style.BRIGHT + "[*] Vendor-Specific Information:")
                print(Fore.GREEN + Style.BRIGHT + f"      Vendor Name: {vendor_name}")
                print(Fore.GREEN + Style.BRIGHT + f"      Data: {vendor_data.hex() if isinstance(vendor_data, bytes) else vendor_data}")

            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + "Use strong passwords, monitor unusual activities")

        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[ERROR] RADIUS packet processing failed: {e}")

    if args.SNMP and packet.haslayer(UDP) and packet[UDP].dport == 161:

        try:
            ip_src = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src if packet.haslayer(IPv6) else "Unknown"
            ip_dst = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst if packet.haslayer(IPv6) else "Unknown"

            community_string = str(packet[SNMP].community) if packet.haslayer(SNMP) else "Unknown"

            packet_key_SNMP = f"{ip_src}-{ip_dst}-{community_string}"

            if packet_key_SNMP in seen_packets["SNMP"]:
                return

            seen_packets["SNMP"].add(packet_key_SNMP)

            print(Fore.WHITE + Style.BRIGHT + '-' * 50)
            print(Fore.WHITE + Style.BRIGHT + "[+] Detected SNMP Packet")
            print(Fore.GREEN + Style.BRIGHT + "[*] Attack Impact: " + Fore.YELLOW + Style.BRIGHT + "Information Gathering")
            print(Fore.GREEN + Style.BRIGHT + "[*] Tools: " + Fore.WHITE + Style.BRIGHT + "snmpwalk, snmpget, snmp_enum, onesixtyone")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Source IP: {Fore.WHITE + ip_src}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] Destination IP: {Fore.WHITE + ip_dst}")
            print(Fore.GREEN + Style.BRIGHT + f"[*] SNMP Community String: {Fore.WHITE + community_string}")

            if community_string.lower() in ["public", "private"]:
                print(Fore.YELLOW + Style.BRIGHT + "[!] Warning: Default SNMP community string used ('public' or 'private'). This is a security risk!")

            if packet.haslayer(SNMP):
                snmp_layer = packet[SNMP]
                if hasattr(snmp_layer, "PDU"):
                    for varbind in getattr(snmp_layer.PDU, "varbindlist", []):
                        oid = varbind.oid.val if hasattr(varbind, "oid") else "Unknown OID"
                        value = varbind.val.val if hasattr(varbind, "val") else "Unknown Value"
                        print(Fore.GREEN + Style.BRIGHT + f"[*] SNMP Query: OID {Fore.WHITE + oid} → Value: {Fore.WHITE + str(value)}")

            print(Fore.CYAN + Style.BRIGHT + "[*] Mitigation: " + Fore.WHITE + Style.BRIGHT + "Restrict SNMP access, use strong community strings, monitor SNMP traffic")

        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"[ERROR] SNMP packet processing failed: {e}")

# list for packets processing
packets = []

# Passive ARP
def passive_arp_monitor(packet):
    if packet.haslayer(ARP):
        arp_op = packet[ARP].op
        op_type = "Request" if arp_op == 1 else "Reply" if arp_op == 2 else "Unknown"
        print(Fore.WHITE + Style.BRIGHT + '-' * 50)
        print(Fore.WHITE + Style.BRIGHT + f"[+] Detected ARP {op_type}")
        print(Fore.YELLOW + Style.BRIGHT + f"[*] ARP {op_type} for IP: " + Fore.WHITE + Style.BRIGHT + packet[ARP].psrc)
        print(Fore.YELLOW + Style.BRIGHT + f"[*] MAC Address: " + Fore.WHITE + Style.BRIGHT + packet[ARP].hwsrc)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', type=str, required=False, help='Interface for traffic listening')
    parser.add_argument('--timer', type=int, help='Time in seconds to capture packets, if not set capture runs indefinitely')
    parser.add_argument('--output', type=str, help='File name where the traffic will be recorded')
    parser.add_argument('--input', type=str, help='File name of the traffic dump')
    parser.add_argument('--passive-arp', action='store_true', help='Passive ARP (Host Discovery)')

    # Individual protocol flags
    parser.add_argument('--MACSec', action='store_true', help='Capture MACSec packets')
    parser.add_argument('--EAPOL', action='store_true', help='Capture EAPOL packets')
    parser.add_argument('--ARP', action='store_true', help='Capture ARP packets')
    parser.add_argument('--CDP', action='store_true', help='Capture CDP packets')
    parser.add_argument('--DTP', action='store_true', help='Capture DTP packets')
    parser.add_argument('--LLDP', action='store_true', help='Capture LLDP packets')
    parser.add_argument('--VLAN', action='store_true', help='Capture VLAN packets')
    parser.add_argument('--S7COMM', action='store_true', help='Capture S7COMM packets')
    parser.add_argument('--OMRON', action='store_true', help='Capture OMRON packets')
    parser.add_argument('--TACACS', action='store_true', help='Capture TACACS+ packets')
    parser.add_argument('--ModbusTCP', action='store_true', help='Capture ModbusTCP packets')
    parser.add_argument('--STP', action='store_true', help='Capture STP packets')
    parser.add_argument('--OSPF', action='store_true', help='Capture OSPF packets')
    parser.add_argument('--EIGRP', action='store_true', help='Capture EIGRP packets')
    parser.add_argument('--BGP', action='store_true', help='Capture BGP packets')
    parser.add_argument('--VRRP', action='store_true', help='Capture VRRP packets')
    parser.add_argument('--VRRPv3', action='store_true', help='Capture VRRPv3 packets')
    parser.add_argument('--HSRP', action='store_true', help='Capture HSRP packets')
    parser.add_argument('--GLBP', action='store_true', help='Capture GLBP packets')
    parser.add_argument('--IGMP', action='store_true', help='Capture IGMP packets')
    parser.add_argument('--LLMNR', action='store_true', help='Capture LLMNR packets')
    parser.add_argument('--NBT_NS', action='store_true', help='Capture NBT-NS packets')
    parser.add_argument('--MDNS', action='store_true', help='Capture MDNS packets')
    parser.add_argument('--DHCP', action='store_true', help='Capture DHCP packets')
    parser.add_argument('--DHCPv6', action='store_true', help='Capture DHCPv6 packets')
    parser.add_argument('--ICMPv6', action='store_true', help='Capture ICMPv6 packets')
    parser.add_argument('--SSDP', action='store_true', help='Capture SSDP packets')
    parser.add_argument('--MNDP', action='store_true', help='Capture MNDP packets')
    parser.add_argument('--SNMP', action='store_true', help='Capture SNMP packets')
    parser.add_argument('--RADIUS', action='store_true', help='Capture RADIUS packets')

    args = parser.parse_args()

    def signal_handler(sig, frame):
        print("\n[!] CTRL+C pressed. Exiting...")
        if args.output and packets:
            try:
                wrpcap(args.output, packets)
                print(Fore.YELLOW + Style.BRIGHT + f"\n[*] Saved {len(packets)} packets to {args.output}")
            except Exception as e:
                print(Fore.RED + Style.BRIGHT + f"Error saving packets to {args.output}: {e}")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    all_flags = [
        'MACSec', 'EAPOL', 'ARP', 'CDP', 'DTP', 'LLDP', 'VLAN', 'S7COMM', 'OMRON', 'TACACS', 'ModbusTCP', 'STP',
        'OSPF', 'EIGRP', 'BGP', 'VRRP', 'VRRPv3', 'HSRP', 'GLBP', 'IGMP', 'LLMNR', 'NBT_NS', 'MDNS', 'DHCP',
        'DHCPv6', 'ICMPv6', 'SSDP', 'MNDP', 'SNMP', 'RADIUS'
    ]

    if not any(getattr(args, flag) for flag in all_flags):
        for flag in all_flags:
            setattr(args, flag, True)

    if not any(vars(args).values()):
        print("[!] Use --help to work with the tool")
        return
    if args.input:
        print("[+] Analyzing pcap file...\n")
        analyze_pcap(args.input, args)
        return
    if os.getuid() != 0:
        print("[!] Sniffing traffic requires root privileges. Please run as root.")
        return
    if args.passive_arp:
        print("[+] Host discovery using Passive ARP\n")
        sniff(iface=args.interface, timeout=args.timer, prn=passive_arp_monitor, store=0)
    elif args.interface:
        print("[+] Start sniffing...\n")
        print("[*] After the protocol is detected - all necessary information about it will be displayed")
        sniff(iface=args.interface, timeout=args.timer if args.timer is not None else None, prn=lambda x: packet_detection(x, args), store=0)

    if packets and args.output:
            try:
                wrpcap(args.output, packets)
                print(Fore.YELLOW + Style.BRIGHT + f"\n[*] Saved {len(packets)} packets to {args.output}")
            except Exception as e:
                print(Fore.RED + Style.BRIGHT + f"Error saving packets to {args.output}: {e}")

if __name__ == "__main__":
    main()
