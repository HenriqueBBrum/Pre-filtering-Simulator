from scapy.all import IP
from scapy.layers.http import * 
from scapy.utils import PcapWriter, PcapReader
from multiprocessing import Pool,Manager,cpu_count
from socket import getservbyport
from os import listdir, getpid
from time import time
import traceback
import collections

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
        pkt_id, ip_pkt_count = 0, 0
        suspicious_pkts = []
        pool = Pool(10)
        suspicious_pkts = Manager().list()
        for pkt in PcapReader(pcap_path + pcap_file):
            if ip_pkt_count > 100:
                break

            if IP in pkt:
                print(pkt_id)
                packet_to_match = PacketToMatch(pkt, rules_dict.keys())
                rules_to_compare = get_pkt_related_rules(packet_to_match, rules_dict)
                if not rules_to_compare:
                    suspicious_pkts.append((pkt_id, rule))
                else:
                    #compare_rules(packet_to_match, pkt_id, rules_to_compare, suspicious_pkts)
                    pool.apply_async(compare_rules, (packet_to_match, pkt_id, rules_to_compare, suspicious_pkts))

                ip_pkt_count+=1
            pkt_id+=1
        pool.close()
        pool.join()

        print(collections.Counter(elem[1][0] for elem in suspicious_pkts))
        print("Time to process", ip_pkt_count+1, "packets against ",len(rules), "rules in seconds: ", time() - start)
        print(len(suspicious_pkts), ip_pkt_count,  pkt_id+1, "\n") # Count IP packets
        #send_pkts_to_NIDS(pcap, suspicious_pkts, "output/"+ruleset_name+"_"+pcap_file.split("-")[0]+"_sus_pkts.pcap")


# Generates the optimal pre-filtering ruleset using most header fields and part of the payload matches
def optimal_pre_filtering_rules():
    # get_header_and_payload_fields()

    # select_optimal_payload_config()

    return []


# Compares a list of packets with rules
def compare_rules(pkt_to_match, pkt_id, rules, suspicious_pkts):
    count = 0
    start = time()
    for rule in rules:
        try:
            if not compare_header_fields(pkt_to_match, rule, rule.pkt_header_fields["proto"]):
                continue

            if not compare_payload(pkt_to_match, rule):
                continue
        except Exception as e:
            print("Exception")
            print(traceback.format_exc())

        suspicious_pkts.append((pkt_id,rule.sids()))
        break                

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
        
    return rules_dict[pkt_proto]+(rules_dict[service] if service in rules_dict.keys() else [])


# Sends the remaining packets to Snort using the desired configuration
def send_pkts_to_NIDS(pcap, suspicious_pkts, output_file):
    suspicious_pkts_pcap = PcapWriter(output_file, append=True, sync=True)
    for match in sorted(suspicious_pkts, key=lambda x: x[0]):
        suspicious_pkts_pcap.write(pcap[match[0]])

    # run os command to send packets to Snort and save the output somewhere
