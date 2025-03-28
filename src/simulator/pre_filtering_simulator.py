import os
import sys
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

# Simulate the pre-filtering of packets based on signature rules]
def pre_filtering_simulation(sim_config, matches, no_content_matches, output_folder, info):
    info["type"] = "pre_filtering"
    pcaps_path = sim_config["pcaps_path"]
    for pcap_file in os.listdir(pcaps_path):
        if "Tuesday_start.pcap" not in pcap_file:
            continue
        current_trace = pcap_file.split(".")[0] # Remove ".pcap" to get day
        print(current_trace)
        info[current_trace] = {}
        start = time()
        suspicious_pkts, temp_info = find_suspicious_packets(pcaps_path+pcap_file, matches, no_content_matches, sim_config["nids_name"], sim_config["scenario"])
      
        info[current_trace]["total_time_to_process"] = time() - start
        info[current_trace].update(temp_info)

        info[current_trace]["number_of_suspicious_pkts"] = len(suspicious_pkts)
        info[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)
        info = compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info)
        print(json.dump(info , sys.stdout, ensure_ascii=False, indent=4))
    return info

# Find the suspicious packets
def find_suspicious_packets(pcap_file, matches, no_content_matches, nids_name, pre_filtering_scenario):
    suspicious_pkts = []
    tcp_stream_tracker = {}
    tls_handshake_tracker, ftp_tracker = set(), set()
    pkt_count, ip_pkt_count = 0, 0
    comparisons_to_match, comparisons_to_content, comparisons_to_pcre = 0, 0, 0
    for scapy_pkt in PcapReader(pcap_file):
        if IP in scapy_pkt:
            if unsupported_protocols(scapy_pkt):
                suspicious_pkt = (pkt_count, "unsupported")
            else:
                pkt = PacketToMatch(scapy_pkt)
                matches_key = get_related_matches_key(pkt, no_content_matches.keys() if pkt.payload_size == 0 else matches.keys()) 
                suspicious_pkt = None
                if pkt.tcp and pre_filtering_scenario != "wang_chang":
                    flow = pkt.header["src_ip"]+str(pkt.header["sport"])+pkt.header["dst_ip"]+str(pkt.header["dport"]) 
                    reversed_flow = pkt.header["dst_ip"]+str(pkt.header["dport"])+pkt.header["src_ip"]+str(pkt.header["sport"]) # Invert order to match flow
                    if "tls" in matches_key and flow not in tls_handshake_tracker and reversed_flow not in tls_handshake_tracker and pkt.payload_buffers["pkt_data"][0][0] == "\x16":
                        suspicious_pkt = (pkt_count, "tls")
                        tls_handshake_tracker.add(flow)
                    else:
                        if nids_name == "suricata":
                            if "ftp" in matches_key and flow not in ftp_tracker and ord(pkt.payload_buffers["pkt_data"][0][0]) <= 0x39:
                                suspicious_pkt = (pkt_count, "ftp")
                                ftp_tracker.add(flow)
                            else:
                                suspicious_pkt = suricata_packet_sampling(pkt, pkt_count, flow, reversed_flow, tcp_stream_tracker)
                        elif nids_name == "snort":
                            if "ftp" in matches_key and flow not in ftp_tracker and ord(pkt.payload_buffers["pkt_data"][0][0]) > 0x39:
                                suspicious_pkt = (pkt_count, "ftp") 
                                ftp_tracker.add(flow) 
                            else:
                                suspicious_pkt = snort_check_stream_tcp(pkt, pkt_count, flow, reversed_flow, tcp_stream_tracker)

                if not suspicious_pkt:
                    if pkt.payload_size == 0:
                        suspicious_pkt, cm, cc, ccpcre = is_packet_suspicious(pkt, pkt_count, matches_key, no_content_matches[matches_key], tcp_stream_tracker)
                    else:
                        suspicious_pkt, cm, cc, ccpcre = is_packet_suspicious(pkt, pkt_count, matches_key, matches[matches_key], tcp_stream_tracker)

                    comparisons_to_match+=cm
                    comparisons_to_content+=cc
                    comparisons_to_pcre+=ccpcre                        

            if suspicious_pkt:
                suspicious_pkts.append(suspicious_pkt)

            ip_pkt_count+=1
        pkt_count+=1

    info = {}
    info["pcap_size"] = pkt_count
    info["avg_num_rules_compared_to"] = comparisons_to_match/pkt_count
    info["avg_num_contents_compared_to"] = comparisons_to_content/pkt_count
    info["avg_num_pcre_compared_to"] = comparisons_to_pcre/pkt_count
    info["pkts_processed"] = ip_pkt_count
    return suspicious_pkts, info

# DNP3, MMS, SMB
unsupported_protocols_port = {135, 139, 445, 502, 651, 802, 3020, 5060, 5061, 5080, 19999, 20000}
# CIP, IEC104 and S7Comm not here
def unsupported_protocols(pkt):
    if TCP in pkt or UDP in pkt:
        if GTPHeader in pkt or GTPHeader_v2 in pkt:
            return True

        transport_layer = pkt.getlayer(UDP) if pkt.getlayer(UDP) else pkt.getlayer(TCP)
        sport = pkt[transport_layer.name].sport
        dport = pkt[transport_layer.name].dport

        if sport in unsupported_protocols_port or dport in unsupported_protocols_port:
            return True

ip_proto = {1:"icmp", 6:"tcp", 17:"udp"}
# Returns the matches key related to the protocol and services of a packet
def get_related_matches_key(pkt, matches_keys):
    proto = pkt.header["ip_proto"]
    pkt_proto = ip_proto[proto] if proto in ip_proto else proto
    applayer_proto =  None
    if pkt.tcp or pkt.udp:
        applayer_proto = get_applayer_proto(pkt, pkt_proto)

    related_matches_key = "ip"
    if pkt_proto in matches_keys:
        related_matches_key = pkt_proto
        if applayer_proto and related_matches_key+"_"+applayer_proto in matches_keys:
            related_matches_key+="_"+applayer_proto

    return related_matches_key

   
port_to_service_map = {446: "drda", 447: "drda", 448: "drda", 1098:"java_rmi", 1099:"java_rmi",
                    1900: "ssdp", 1935: "rtmp", 5500: "vnc",  5800: "vnc", 5900: "vnc", 5938: "teamview"}


change_map = {"http-alt": "http", "microsoft-ds": "netbios-ssn", 
              "domain": "dns", "mdns":"dns", "https": "tls",
              "mysql-proxy": "mysql", "auth": "ident", "imap2": "imap",
              "imaps": "imap", "pop3s": "pop3", "telnets": "telnet",
              "ftps-data": "ftp-data", "ftps":"ftp", "dhcpv6-client": "dhcp",
              "dhcpv6-server": "dhcp", "syslog-tls": "syslog",
              "ircs-u": "irc", "radius-acct": "radius", "bgpd": "bgp",
              "sip-tls": "sip", "ms-wbt-server": "rdp", "epmap": "dcerpc"}

# Returns the applayer proto if it is a valid one and the payload for the layer4 protocol is more than 0
def get_applayer_proto(pkt, proto_str):
    applayer_proto = None
    try:
        applayer_proto = getservbyport(pkt.header["dport"], proto_str)
    except Exception as e:
        try:
            applayer_proto = getservbyport(pkt.header["sport"], proto_str)
        except  Exception as e:
            return None
        
    if not applayer_proto:
        applayer_proto = port_to_service_map.get(pkt.header["dport"])

    if not applayer_proto:
        applayer_proto = port_to_service_map.get(pkt.header["sport"])

    if applayer_proto:
        if pkt.payload_size == 0:
            applayer_proto = proto_str

        if applayer_proto == "http" and not (pkt.http_res or pkt.http_req):
            applayer_proto = proto_str
            
        if applayer_proto in change_map: # getservbyport and Snort and Suricata have different ideas on the app layer proto for the same port
            applayer_proto = change_map[applayer_proto]
            
    return applayer_proto 


# Check Snort TCP flow requirements
def snort_check_stream_tcp(pkt, pkt_count, flow, reversed_flow, tcp_stream_tracker):
    suspicious_pkt = None

    msg = "stream_tcp"
    stream_tcp = False    
    if flow in tcp_stream_tracker and pkt.header["flags"] == 16 and pkt.header["seq"] == tcp_stream_tracker[flow]["seq"]:
        stream_tcp = True
    elif flow in tcp_stream_tracker and pkt.header["flags"] & 24 == 24 and pkt.header["ack"] == tcp_stream_tracker[flow]["ack"]:
        stream_tcp = True
    elif reversed_flow in tcp_stream_tracker and pkt.header["flags"] == 16 and pkt.header["seq"] == tcp_stream_tracker[reversed_flow]["ack"]:
        stream_tcp = True
    elif reversed_flow in tcp_stream_tracker and pkt.header["flags"] & 24 == 24 and pkt.header["ack"] == tcp_stream_tracker[reversed_flow]["seq"]:
        stream_tcp = True

    if "R" in pkt.header["flags"]:
        stream_tcp = True
        msg = "reset"
    elif "F" in pkt.header["flags"]:
        stream_tcp = True
        msg = "fin"
        remove_flow(flow, reversed_flow, tcp_stream_tracker)

    if stream_tcp:
        suspicious_pkt = (pkt_count, msg)
    else:
        remove_flow(flow, reversed_flow, tcp_stream_tracker)

    return suspicious_pkt

# Check Suricata TCP flow requirements
def suricata_packet_sampling(pkt, pkt_count, flow, reversed_flow, tcp_stream_tracker):
    if pkt.header["flags"] == 2 or pkt.header["flags"] == 18: # SYN or SYN +ACK
        return (pkt_count, "tcp_handshake")

    suspicious_pkt = None
    msg = "stream_tcp"
    stream_tcp = False    
    if flow in tcp_stream_tracker and pkt.header["flags"] == 16 and pkt.header["seq"] == tcp_stream_tracker[flow]["seq"]:
        stream_tcp = True
    elif flow in tcp_stream_tracker and pkt.header["flags"] & 24 == 24 and pkt.header["ack"] == tcp_stream_tracker[flow]["ack"]:
        stream_tcp = True
    # elif reversed_flow in tcp_stream_tracker and pkt.header["ack"] == tcp_stream_tracker[reversed_flow]["seq"]:
    #     stream_tcp = True
    elif reversed_flow in tcp_stream_tracker and pkt.header["flags"] == 16 and pkt.header["seq"] == tcp_stream_tracker[reversed_flow]["ack"]:
        stream_tcp = True
    elif reversed_flow in tcp_stream_tracker and pkt.header["flags"] & 24 == 24 and pkt.header["ack"] == tcp_stream_tracker[reversed_flow]["seq"]:
        stream_tcp = True

    if "R" in pkt.header["flags"]:
        stream_tcp = True
        msg = "reset"
    # elif "F" in pkt.header["flags"]:
    #     stream_tcp = True
    #     msg = "fin"
    #     remove_flow(flow, reversed_flow, tcp_stream_tracker)

   
    if stream_tcp:
        suspicious_pkt = (pkt_count, msg)
    else:
        remove_flow(flow, reversed_flow, tcp_stream_tracker)

    return suspicious_pkt

def remove_flow(flow, reversed_flow, tcp_stream_tracker):
    if flow in tcp_stream_tracker:
        tcp_stream_tracker.pop(flow)
    elif reversed_flow in tcp_stream_tracker:
        tcp_stream_tracker.pop(reversed_flow)


# Checks if a packet is suspicous, unsupported or is in a tcp stream
def is_packet_suspicious(pkt, pkt_count, proto, matches, tcp_stream_tracker):
    comparisons_to_match, comparisons_to_content, comparisons_to_pcre = 0, 0, 0
    for header_group in matches:
        try:
            comparisons_to_match+=1
            if not matched_ip_and_port(pkt, matches[header_group][0]): 
                continue
            comparisons_to_match-=1
            # Matched the groups' ip and port header, compare with the other fields of each rule in this group
            for match in matches[header_group]:
                if match.max_content_size > pkt.payload_size: # All further matches have at least the same max_content_size as the current match
                    break
                
                comparisons_to_match+=1
                if not matched_header_fields(pkt, match):
                    continue

                matched, compared_to_content, compared_to_pcre = matched_payload(pkt, match)
                comparisons_to_content+=compared_to_content
                comparisons_to_pcre+=compared_to_pcre
                if not matched:
                    continue
                
                if pkt.tcp: # and ("http" in proto or "tls" in proto):
                    flow = pkt.header["src_ip"]+str(pkt.header["sport"])+pkt.header["dst_ip"]+str(pkt.header["dport"])
                    if pkt.header["flags"] == "A":
                        tcp_stream_tracker[flow] = {"seq": pkt.header["seq"], "ack": pkt.header["ack"]}    
                    elif pkt.header["flags"] == "PA":
                        tcp_stream_tracker[flow] = {"seq": pkt.header["seq"]+pkt.payload_size, "ack": pkt.header["ack"]}

                return (pkt_count, match.sids()[0]),comparisons_to_match, comparisons_to_content, comparisons_to_pcre
        except Exception as e:
            print("Exception: ", traceback.format_exc())
            return (pkt_count, "error"), comparisons_to_match, comparisons_to_content, comparisons_to_pcre

    return None, comparisons_to_match, comparisons_to_content, comparisons_to_pcre