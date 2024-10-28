from scapy.all import IP
from scapy.layers.http import * 
from scapy.utils import PcapWriter,PcapReader,rdpcap
from multiprocessing import Pool,Manager,cpu_count
from socket import getservbyport
from os import listdir, getpid
from time import time
import traceback
import collections
import sys

from .header_matching import compare_header_fields
from .payload_matching import compare_payload
from .packet_to_match import PacketToMatch

def pre_filtering_simulation(rules, ruleset_name, pcap_path="/home/hbeckerbrum/NFSDatasets/CICIDS2017/"):
    # Find the optimal pre-filtering subset   
    # pre_filtering_rules = optimal_pre_filtering_rules()
   
    rules_dict = {}
    for rule in rules:
        proto = rule.pkt_header_fields["proto"]
        if proto not in rules_dict:
            rules_dict[proto] = [rule]
        else:
            rules_dict[proto].append(rule)

    rules_dict["icmp"] = rules_dict["ip"]+rules_dict["icmp"]
    rules_dict["tcp"] = rules_dict["ip"]+rules_dict["tcp"]
    rules_dict["udp"] = rules_dict["ip"]+rules_dict["udp"]

    for pcap_file in listdir(pcap_path):
        if "Friday" not in pcap_file:
            continue
        start = time()
        pkt_id, ip_pkt_count, sus_count = 0, 0, 0
        matched_rules = {}
        print("Begin processing file: ", pcap_file)
        sys.stdout.flush()

        suspicious_pkts_output = "output/"+ruleset_name+"_"+pcap_file.split("-")[0]+"_sus_pkts.pcap"
        pcap_writer = PcapWriter(suspicious_pkts_output, append=True, sync=True)
        for pkt in PcapReader(pcap_path + pcap_file):
            if IP in pkt:
                packet_to_match = PacketToMatch(pkt, rules_dict.keys())
                rules_to_compare = get_pkt_related_rules(packet_to_match, rules_dict)
                for rule in rules_to_compare:
                    try:
                        if not compare_header_fields(packet_to_match, rule, rule.pkt_header_fields["proto"]):
                            continue

                        if not compare_payload(packet_to_match, rule):
                            continue
                    except Exception as e:
                        print("Exception")
                        print(traceback.format_exc())

                    sus_count+=1
                    rule_sids = rule.sids()[0]
                    matched_rules[rule_sids] = matched_rules[rule_sids]+1 if rule_sids in matched_rules else 1 
                    pcap_writer.write(pkt)
                    break 
                ip_pkt_count+=1
            pkt_id+=1
        pcap_writer.close()
        print(matched_rules)
        print("Time to process", ip_pkt_count+1, "packets against ",len(rules), "rules in seconds: ", time() - start)
        print(sus_count, ip_pkt_count,  pkt_id+1, "\n") # Count IP packets
        print("Finished with file: ", pcap_file)


# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def optimal_pre_filtering_rules():
    # get_header_and_payload_fields()

    # select_optimal_payload_config()

    return []


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
            service = getservbyport(pkt[pkt_proto.upper()].sport, pkt_proto)
        except:
            try:
                service = getservbyport(pkt[pkt_proto.upper()].dport, pkt_proto)
            except:
                service = None

        if service == "http-alt":
            service == "http"

        if service == "http" and (HTTPRequest not in pkt or HTTPResponse not in pkt):
            service = None
        
    return rules_dict[pkt_proto]+(rules_dict[service] if service in rules_dict else [])
