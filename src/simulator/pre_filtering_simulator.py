import os
import json
import traceback
from time import time
from collections import Counter
from socket import getservbyport


from scapy.all import IP,UDP,TCP 
from scapy.utils import PcapReader 
from scapy.contrib.gtp import GTPHeader 
from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader_v2 

from .header_matching import matched_ip_and_port, matched_header_fields
from .payload_matching import matched_payload
from .packet_to_match import PacketToMatch

from .analysis import compare_to_baseline

import sys
sys.path.append("..")
from utils.ports import SIP_PORTS,SMB_PORTS



# Simulate the pre-filtering of packets based on signature rules]
def pre_filtering_simulation(sim_config, matches, output_folder, info):
    info["type"] = "pre_filtering"
    pcaps_path = sim_config["pcaps_path"]

    for pcap_file in os.listdir(pcaps_path):
        if "Friday_start" not in pcap_file:
            continue

        current_trace = pcap_file.split(".")[0] # Remove ".pcap" to get day
        print(current_trace)
        info[current_trace] = {}

        start = time()
        suspicious_pkts, temp_info = find_suspicious_packets(pcaps_path+pcap_file, matches)
      
        info[current_trace]["total_time_to_process"] = time() - start
        info[current_trace].update(temp_info)

        info[current_trace]["number_of_suspicious_pkts"] = len(suspicious_pkts)
        info[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)
        #info = compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info)
        print(json.dump(info , sys.stdout, ensure_ascii=False, indent=4))
    return info

# Find the suspicious packets
def find_suspicious_packets(pcap_file, matches):
    suspicious_pkts = []
    time_to_process = []
    tcp_tracker = {}
    ftp_tracker = set()
    pkt_count, ip_pkt_count = 0, 0
    for scapy_pkt in PcapReader(pcap_file):
        if IP in scapy_pkt:
            start = time()
            if unsupported_protocols(scapy_pkt):
                suspicious_pkt = (pkt_count, "unsupported")
            else:
                pkt = PacketToMatch(scapy_pkt)
                proto, related_matches = get_related_matches(pkt, matches) 
                suspicious_pkt = is_packet_suspicious(pkt, pkt_count, related_matches, tcp_tracker)
            
                if not suspicious_pkt and pkt.tcp: 
                    if "ftp" not in proto:  
                        suspicious_pkt = check_stream_tcp(pkt, pkt_count, tcp_tracker)
                    else:
                        flow = pkt.header["src_ip"]+str(pkt.header["sport"])+pkt.header["dst_ip"]+str(pkt.header["dport"])
                        if flow not in ftp_tracker and "pass " in pkt.payload_buffers["pkt_data"][1]:
                            suspicious_pkt = (pkt_count, "ftp")
                            ftp_tracker.add(flow)

            if suspicious_pkt:
                suspicious_pkts.append(suspicious_pkt)

            ip_pkt_count+=1
            time_to_process.append(time()-start)
            if ip_pkt_count > 5000:
                break
        pkt_count+=1

    info = {}

    info["pcap_size"] = pkt_count
    info["avg_pkt_processing_time"] = sum(time_to_process)/len(time_to_process)
    info["pkts_processed"] = ip_pkt_count
    
    return suspicious_pkts, info

# CIP, IEC104 and S7Comm not here
def unsupported_protocols(pkt):
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

        if sport == 651 or dport == 651: # MMS
            return True 

        if sport == 502 or sport == 802 or dport == 502 or dport == 802: # DNP3
            return True

        if sport in SIP_PORTS or dport in SIP_PORTS: # SIP
            return True 

        if sport in SMB_PORTS or dport in SMB_PORTS: #SMB
            return True

ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}
# Returns the rules related to the protocol and services of a packet
def get_related_matches(pkt, matches):
    pkt_proto = ip_proto.get(pkt.header["ip_proto"], "ip")
    applayer_proto =  None
    if pkt.tcp or pkt.udp:
        applayer_proto = get_applayer_proto(pkt_proto, pkt.header["sport"], pkt.header["dport"])

    related_matches_key = "ip"
    if pkt_proto in matches:
        related_matches_key = pkt_proto
        if applayer_proto and related_matches_key+applayer_proto in matches:
            related_matches_key+=applayer_proto

    return related_matches_key, matches[pkt_proto]

change_map = {"http-alt": "http", "microsoft-ds": "netbios-ssn", "domain": "dns", "mdns":"dns", "https": None}
def get_applayer_proto(proto_str, sport, dport):
    applayer_proto = None
    try:
        applayer_proto = getservbyport(sport, proto_str)
    except Exception as e:
        try:
            applayer_proto = getservbyport(dport, proto_str)
        except  Exception as e:
            return None
        
    if applayer_proto:
        if applayer_proto in change_map:
            applayer_proto = change_map[applayer_proto]
            
    return applayer_proto 

# Checks if a packet is suspicous, unsupported or is in a tcp stream
def is_packet_suspicious(pkt, pkt_count, matches, tcp_tracker):
    for header_group in matches:
        #try:
            if not matched_ip_and_port(pkt, matches[header_group][0]): 
                continue
        
            # Matched the groups' ip and port header, compare with the other fields of each rule in this group
            for match in matches[header_group]:
                if not matched_header_fields(pkt, match):
                    continue

                # if not matched_payload(pkt, rule):
                #     continue
                
                if pkt.tcp:
                    flow = pkt.header["src_ip"]+str(pkt.header["sport"])+pkt.header["dst_ip"]+str(pkt.header["dport"])
                    if pkt.header["flags"] == "A":
                        tcp_tracker[flow] = {"seq": pkt.header["seq"], "ack": pkt.header["ack"]}    
                    elif pkt.header["flags"] == "PA":
                        tcp_tracker[flow] = {"seq": pkt.header["seq"]+pkt.payload_size, "ack": pkt.header["ack"]}   

                return (pkt_count, match.sids()[0])
        # except Exception as e:
        #     print("Exception: ", traceback.format_exc())
        #     return (pkt_count, "error")
        
    return None


def check_stream_tcp(pkt, pkt_count, tcp_tracker):
    suspicious_pkt = None
    flow = pkt.header["src_ip"]+str(pkt.header["sport"])+pkt.header["dst_ip"]+str(pkt.header["dport"])
    reversed_flow = pkt.header["dst_ip"]+str(pkt.header["dport"])+pkt.header["src_ip"]+str(pkt.header["sport"]) #Invert order to match flow

    stream_tcp = False
    if flow in tcp_tracker and pkt.header["flags"] == "A" and pkt.header["seq"] == tcp_tracker[flow]["seq"]:
        stream_tcp = True
    elif flow in tcp_tracker and "PA" in pkt.header["flags"] and pkt.header["ack"] == tcp_tracker[flow]["ack"]:
        stream_tcp = True
    elif reversed_flow in tcp_tracker and pkt.header["flags"]  == "A" and pkt.header["seq"] == tcp_tracker[reversed_flow]["ack"]:
        stream_tcp = True
    elif reversed_flow in tcp_tracker and "PA" in pkt.header["flags"] and pkt.header["ack"] == tcp_tracker[reversed_flow]["seq"]:
        stream_tcp = True

    if "R" in pkt.header["flags"]:
        stream_tcp = True
    elif "F" in pkt.header["flags"] :
        stream_tcp = True
        remove_flow(tcp_tracker, flow, reversed_flow)

    if stream_tcp:
        suspicious_pkt = (pkt_count, "stream_tcp")
    else:
        remove_flow(tcp_tracker, flow, reversed_flow)

    return suspicious_pkt, tcp_tracker

def remove_flow(flow, reversed_flow, tcp_tracker):
    if flow in tcp_tracker:
        tcp_tracker.pop(flow)
    elif reversed_flow in tcp_tracker:
        tcp_tracker.pop(reversed_flow)
