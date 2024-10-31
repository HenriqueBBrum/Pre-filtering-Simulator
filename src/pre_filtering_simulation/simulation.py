from scapy.all import IP,UDP,TCP # type: ignore
from scapy.layers.http import HTTPRequest,HTTPResponse # type: ignore
from scapy.utils import PcapWriter,PcapReader # type: ignore
from scapy.contrib.gtp import GTPHeader # type: ignore
from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader_v2 # type: ignore


from socket import getservbyport
from os import listdir, getpid
from time import time
import traceback
import collections
import sys

from .header_matching import compare_header_fields
from .payload_matching import compare_payload
from .packet_to_match import PacketToMatch

# Main simulation function where packets are compared against the pre-filtering rules
def pre_filtering_simulation(rules, ruleset_name, pcap_path="/home/hbeckerbrum/Optmized-pre-filtering-for-NIDS/selected_pcaps/pcaps"):
    # Find the optimal pre-filtering subset   
    pre_filtering_rules = get_pre_filtering_rules(rules)
   
    for pcap_file in listdir(pcap_path):
        start = time()
        pkt_count, ip_pkt_count, sus_count = 0, 0, 0
        matched_rules = {"0/0": 0}
        print("Begin processing file: ", pcap_file)
        sys.stdout.flush()

        suspicious_pkts_output = "output/pcaps/"+ruleset_name+"_"+pcap_file.split("-")[0]+"_sus_pkts.pcap"
        pcap_writer = PcapWriter(suspicious_pkts_output, append=False, sync=True)
        for pkt in PcapReader(pcap_path + pcap_file):
            if IP in pkt:
                if unsupported_protocol(pkt):
                    sus_count+=1
                    matched_rules["0/0"] = matched_rules["0/0"]+1
                    pcap_writer.write(pkt)
                else:
                    packet_to_match = PacketToMatch(pkt, pre_filtering_rules.keys())
                    rules_to_compare = get_pkt_related_rules(packet_to_match, pre_filtering_rules)
                    for rule in rules_to_compare:
                        rule_sids = "0/0"
                        try:
                            if not compare_header_fields(packet_to_match, rule, rule.pkt_header_fields["proto"]):
                                continue

                            if not compare_payload(packet_to_match, rule):
                                continue

                            rule_sids = rule.sids()[0]
                        except Exception as e:
                            print("Exception")
                            print(traceback.format_exc())

                        sus_count+=1
                        matched_rules[rule_sids] = matched_rules[rule_sids]+1 if rule_sids in matched_rules else 1 
                        pcap_writer.write(pkt)
                        break 
                ip_pkt_count+=1
            pkt_count+=1
        pcap_writer.close()
        print(matched_rules)
        print("Time to process", ip_pkt_count, "packets against ",len(rules), "rules in seconds: ", time() - start)
        print("Suspicious packets:", sus_count, "IP packets:", ip_pkt_count, "Packets:", pkt_count, "\n") # Count IP packets
        print("Finished with file: ", pcap_file)
        print("*"*50)
            
# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def get_pre_filtering_rules(rules):
    rules_dict = {}
    for rule in rules:
        # if rule_not_supported(rule):
        #     continue

        proto = rule.pkt_header_fields["proto"]
        if proto not in rules_dict:
            rules_dict[proto] = [rule]
        else:
            rules_dict[proto].append(rule)

    rules_dict["icmp"] = rules_dict["ip"]+rules_dict["icmp"]
    rules_dict["tcp"] = rules_dict["ip"]+rules_dict["tcp"]
    rules_dict["udp"] = rules_dict["ip"]+rules_dict["udp"]
    
    return rules_dict


ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}
# Returns the rules related to the protocol and services of a packet
def get_pkt_related_rules(pkt_to_match, rules_dict):
    pkt_proto = ip_proto.get(pkt_to_match.header["ip_proto"], "ip")
    if ((pkt_proto == "udp" and not pkt_to_match.upd_in_pkt) or 
                (pkt_proto == "tcp" and not pkt_to_match.tcp_in_pkt) or (pkt_proto == "icmp" and not pkt_to_match.icmp_in_pkt)):
        pkt_proto = "ip"
    
    service = None
    if pkt_to_match.upd_in_pkt or pkt_to_match.tcp_in_pkt:
        try:
            service = getservbyport(pkt_to_match[pkt_proto.upper()].dport, pkt_proto)
        except:
            try:
                service = getservbyport(pkt_to_match[pkt_proto.upper()].sport, pkt_proto)
            except:
                service = None

        if service == "http-alt":
            service == "http"

        if service == "http" and (HTTPRequest not in pkt_to_match or HTTPResponse not in pkt_to_match):
            service = None
        
    return rules_dict[pkt_proto]+(rules_dict[service] if service in rules_dict else [])



sip_ports = {5060, 5061, 5080}
# CIP, IEC104 and S7Comm not here
def unsupported_protocol(pkt):
     if TCP in pkt or UDP in pkt:
        if GTPHeader in pkt or GTPHeader_v2 in pkt:
            return True
 
        transport_layer = pkt.getlayer(UDP) if pkt.getlayer(UDP) else pkt.getlayer(TCP)
        sport = pkt[transport_layer.name].sport
        dport = pkt[transport_layer.name].dport

        if sport == 19999 or sport == 20000 or dport == 19999 or dport == 20000: # DNP3
            return True

        if sport == 135 or dport == 135: # DCE-RPC
            return True 

        if sport in sip_ports or dport in sip_ports: # SIP
            return True 

        if sport == 651 or dport == 651: # MMS
            return True 

        if sport == 502 or sport == 802 or dport == 502 or dport == 802: # DNP3
            return True