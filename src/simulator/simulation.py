# from scapy.all import IP,UDP,TCP 
# from scapy.utils import rdpcap, PcapReader, PcapWriter 
# from scapy.contrib.gtp import GTPHeader 
# from scapy.contrib.gtp_v2 import GTPHeader as GTPHeader_v2 

from pylibpcap.pcap import rpcap


from multiprocessing import Manager,Process,cpu_count
from collections import Counter

from socket import getservbyport
import os
from time import time
import traceback
import json
import subprocess

from .header_matching import matched_ip_and_port, matched_header_fields
from .payload_matching import matched_payload
from .packet_to_match import PacketToMatch
from .packet import Packet, IPV4, TCP, UDP

import sys
#sys.tracebacklimit = 0
sys.path.append("..")
from utils.ports import SIP_PORTS,SMB_PORTS

# Flow sampling simulation to compare againast our pre-filtering proposal. time_threshold in seconds
def flow_sampling_simulation(sim_config, output_folder):
    info = {"type": "flow_sampling"}

    pcaps_path = sim_config["pcaps_path"]
    for pcap_file in os.listdir(pcaps_path):
        current_trace = pcap_file.split(".")[0] # Remove .pcap to get day
        info[current_trace] = {}
    
        start = time()
        suspicious_pkts, temp_info = sample_flows(pcaps_path+pcap_file, sim_config["flow_count_threshold"], sim_config["time_threshold"])

        info[current_trace]["total_time_to_process"] = time() - start
        info[current_trace].update(temp_info)
        
        info[current_trace]["number_of_suspicious_pkts"] = len(suspicious_pkts)
        info[current_trace]["suspicious_pkts_counter"] = Counter(elem[1] for elem in suspicious_pkts)

        info = compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info)
    return info

# Run the flow sampling method over the packets in the PCAP
def sample_flows(pcap_file, flow_count_threshold, time_threshold):
    pkt_count, ip_pkt_count = 0, 0
    suspicious_pkts = []
    time_to_process = []
    flow_tracker = {} # One entry is (current_count, last_pkt_time)

    for len, t, pkt in rpcap(pcap_file):
        parsed_pkt = Packet(pkt, len)
        if parsed_pkt.layer3_proto == IPV4:
            start = time()
            if pkt.layer4_proto == TCP or pkt.layer4_proto == UDP:
                five_tuple = pkt.layer4_proto_str+pkt.src_ip+str(pkt.src_port)+pkt.dst_ip+str(pkt.dst_port) # Bidirectional flows?
            else:
                five_tuple = pkt.layer4_proto_str+pkt.src_ip+pkt.dst_ip

            if five_tuple not in flow_tracker:
                flow_tracker[five_tuple] = (1, pkt.time)
                suspicious_pkts.append((pkt_count, "first_time"))
            else:
                last_pkt_time = flow_tracker[five_tuple][1]
                if pkt.time-last_pkt_time >= time_threshold:
                    flow_tracker[five_tuple] = (1, pkt.time)
                    suspicious_pkts.append((pkt_count, "time_reset"))
                else:
                    flow_tracker[five_tuple] = (flow_tracker[five_tuple][0]+1, pkt.time)
                    if flow_tracker[five_tuple][0] < flow_count_threshold:
                        suspicious_pkts.append((pkt_count, "within_flow_threhold"))

            ip_pkt_count+=1
            time_to_process.append(time()-start)
        pkt_count+=1

    info = {}

    info["pcap_size"] = pkt_count
    info["avg_pkt_processing_time"] = sum(time_to_process)/len(time_to_process)
    info["pkts_processed"] = ip_pkt_count
    info["number_of_flows"] = len(flow_tracker.keys())
    info["top_five_biggest_flows"] = [x[0] for x in sorted(list(flow_tracker.values()), key=lambda x: x[0], reverse=True)[:5]]
    return suspicious_pkts, info



# Simulate the pre-filtering of packets based on signature rules]
def pre_filtering_simulation(sim_config, matches, _info, output_folder):
    info = _info | {"type": "pre_filtering"}
    pcaps_path = sim_config["pcaps_path"]

    for pcap_file in os.listdir(pcaps_path):
        if "Friday" not in pcap_file:
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
        # info = compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info)
        # print(json.dump(info , sys.stdout, ensure_ascii=False, indent=4))
    return info

# Find the suspicious packets
def find_suspicious_packets(pcap_file, matches):
    suspicious_pkts = []
    time_to_process = []
    tcp_tracker = {}
    ftp_tracker = set()
    pkt_count, ip_pkt_count = 0, 0
    for len, t, pkt in rpcap(pcap_file):
        parsed_pkt = Packet(pkt, len)
        if parsed_pkt.layer3_proto == IPV4:
            #print(ip_pkt_count)
            start = time()
            
            suspicious_pkt, tcp_tracker, ftp_tracker = is_packet_suspicious(parsed_pkt, pkt_count, matches, tcp_tracker, ftp_tracker)
            if suspicious_pkt:
                suspicious_pkts.append(suspicious_pkt)

            ip_pkt_count+=1
            time_to_process.append(time()-start)
           
            #input()

        pkt_count+=1

    info = {}
    info["pcap_size"] = pkt_count
    #print(time_to_process)
    #info["avg_pkt_processing_time"] = sum(time_to_process)/len(time_to_process)
    info["pkts_processed"] = ip_pkt_count
    
    return suspicious_pkts, info



# Checks if a packet is suspicous, unsupported or is in a tcp stream

def is_packet_suspicious(pkt, pkt_count, matches, tcp_tracker, ftp_tracker):
    suspicious_pkt = None
    if unsupported_protocols(pkt.layer4_proto, pkt.src_port, pkt.dst_port):
        suspicious_pkt = (pkt_count, "unsupported")
    else:
        related_matches_key = "ip"
        if pkt.layer4_proto_str and pkt.layer4_proto_str in matches:
            related_matches_key = pkt.layer4_proto_str
            if pkt.applayer_proto and pkt.applayer_proto in matches:
                related_matches_key+=pkt.applayer_proto
        
        # print(related_matches_key, len(matches[related_matches_key].items()))
        for key, header_group_matches in matches[related_matches_key].items():
            if suspicious_pkt:
                break
                
            if not matched_ip_and_port(pkt, header_group_matches[0]): 
                continue

            for match in header_group_matches:

                if not matched_header_fields(pkt, match):
                    continue

                # if not matched_payload(pkt_to_match, match):
                #     continue
                    
            # try:
            #     if not matched_ip_and_port(pkt, header_group_matches[0]): 
            #         continue
            
            #     # Matched the groups' ip and port header, compare with the other fields of each match in this group
            #     for match in header_group_matches:
            #         if not matched_header_fields(pkt, match):
            #             continue

            #         # if not matched_payload(pkt_to_match, match):
            #         #     continue
                    
            #         # suspicious_pkt = (pkt_count, match.sids()[0])
            #         # if pkt_to_match.tcp_in_pkt:
            #         #     flow = pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"])+pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])
            #         #     if pkt_to_match.header["flags"] == "A":
            #         #         tcp_tracker[flow] = {"seq": pkt_to_match.header["seq"], "ack": pkt_to_match.header["ack"]}    
            #         #     elif pkt_to_match.header["flags"] == "PA":
            #         #         tcp_tracker[flow] = {"seq": pkt_to_match.header["seq"]+pkt_to_match.payload_size, "ack": pkt_to_match.header["ack"]}   

            #         break
            # except Exception as e:
            #     print("Exception: ", traceback.format_exc())
            #     suspicious_pkt = (pkt_count, "error")

            # if not suspicious_pkt and pkt_to_match.tcp_in_pkt: 
            #     if service != "ftp":  
            #         suspicious_pkt, tcp_tracker = check_stream_tcp(pkt_to_match, tcp_tracker, pkt_count)
            #     else:
            #         flow = pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"])+pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])
            #         if service == "ftp" and flow not in ftp_tracker and "pass " in pkt_to_match.payload_buffers["nocase"]["pkt_data"]:
            #             suspicious_pkt = (pkt_count, "ftp")
            #             ftp_tracker.add(flow)
    
    return suspicious_pkt, tcp_tracker, ftp_tracker

# CIP, IEC104 and S7Comm not here
def unsupported_protocols(layer_4_proto, src_port, dst_port):
     if layer_4_proto == TCP or layer_4_proto == UDP:
        # if GTPHeader in pkt or GTPHeader_v2 in pkt:
        #     return True
 
        if src_port == 19999 or src_port == 20000 or dst_port == 19999 or dst_port == 20000: # DNP3
            return True

        if src_port == 135 or dst_port == 135: # DCE-RPC
            return True 

        if src_port == 651 or dst_port == 651: # MMS
            return True 

        if src_port == 502 or src_port == 802 or dst_port == 502 or dst_port == 802: # DNP3
            return True
        
        if src_port in SIP_PORTS or dst_port in SIP_PORTS: # SIP
            return True 
        
        if src_port in SMB_PORTS or dst_port in SMB_PORTS: #SMB
            return True




# def check_stream_tcp(pkt_to_match, tcp_tracker, pkt_count):
#     suspicious_pkt = None
#     flow = pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"])+pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])
#     reversed_flow = pkt_to_match.header["dst_ip"]+str(pkt_to_match.header["dport"])+pkt_to_match.header["src_ip"]+str(pkt_to_match.header["sport"]) #Invert order to match flow

#     stream_tcp = False
#     if flow in tcp_tracker and pkt_to_match.header["flags"] == "A" and pkt_to_match.header["seq"] == tcp_tracker[flow]["seq"]:
#         stream_tcp = True
#     elif flow in tcp_tracker and "PA" in pkt_to_match.header["flags"] and pkt_to_match.header["ack"] == tcp_tracker[flow]["ack"]:
#         stream_tcp = True
#     elif reversed_flow in tcp_tracker and pkt_to_match.header["flags"]  == "A" and pkt_to_match.header["seq"] == tcp_tracker[reversed_flow]["ack"]:
#         stream_tcp = True
#     elif reversed_flow in tcp_tracker and "PA" in pkt_to_match.header["flags"] and pkt_to_match.header["ack"] == tcp_tracker[reversed_flow]["seq"]:
#         stream_tcp = True

#     if "R" in pkt_to_match.header["flags"]:
#         stream_tcp = True
#     elif "F" in pkt_to_match.header["flags"] :
#         stream_tcp = True
#         tcp_tracker = remove_flow(tcp_tracker, flow, reversed_flow)

#     if stream_tcp:
#         suspicious_pkt = (pkt_count, "stream_tcp")
#     else:
#         tcp_tracker = remove_flow(tcp_tracker, flow, reversed_flow)

#     return suspicious_pkt, tcp_tracker

# def remove_flow(tcp_tracker, flow, reversed_flow):
#     if flow in tcp_tracker:
#         tcp_tracker.pop(flow)
#     elif reversed_flow in tcp_tracker:
#         tcp_tracker.pop(reversed_flow)

#     return tcp_tracker




def compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info): 
    baseline_pcap = sim_config["pcaps_path"]+current_trace+".pcap"

    suspicious_pkts_pcap = get_suspicious_pkts_pcap(baseline_pcap, suspicious_pkts, output_folder, current_trace)
    suspicious_pkts_alert_file, nids_processing_time = nids_with_suspicious_pcap(suspicious_pkts_pcap, sim_config, output_folder, current_trace)
    info[current_trace]["nids_processing_time"] = nids_processing_time

    baseline_pkt_alerts, baseline_flow_alerts = parse_alerts(sim_config["baseline_alerts_path"]+current_trace+".txt") # Baseline alerts
    experiment_pkt_alerts, experiment_flow_alerts = parse_alerts(suspicious_pkts_alert_file)

    # Alert metrics for individual packets
    info[current_trace]["baseline_pkt_alerts"] = len(baseline_pkt_alerts)
    info[current_trace]["experiment_pkt_alerts"] =  len(experiment_pkt_alerts)
    info[current_trace]["pkt_alerts_true_positive"] = len(set(baseline_pkt_alerts) & set(experiment_pkt_alerts))
    info[current_trace]["pkt_alerts_false_negative"] = len(set(baseline_pkt_alerts) - set(experiment_pkt_alerts))
    info[current_trace]["pkt_alerts_false_positive"] = len(set(experiment_pkt_alerts) - set(baseline_pkt_alerts))

    # Alert metrics for flows
    info[current_trace]["baseline_flow_alerts"] = len(baseline_flow_alerts)
    info[current_trace]["experiment_flow_alerts"] =  len(experiment_flow_alerts)
    info[current_trace]["flow_alerts_true_positive"] = len(set(baseline_flow_alerts) & set(experiment_flow_alerts))
    info[current_trace]["flow_alerts_false_negative"] = len(set(baseline_flow_alerts) - set(experiment_flow_alerts))
    info[current_trace]["flow_alerts_false_positive"] = len(set(experiment_flow_alerts) - set(baseline_flow_alerts))

    # counter = {}
    # for key in set(baseline_pkt_alerts.keys()) - set(experiment_pkt_alerts.keys()):
    #     print(key, baseline_pkt_alerts[key]["rule"], baseline_pkt_alerts[key]["proto"], baseline_pkt_alerts[key]["src_ap"], baseline_pkt_alerts[key]["dst_ap"])
    #     if baseline_pkt_alerts[key]["rule"] in counter:
    #         counter[baseline_pkt_alerts[key]["rule"]]+=1
    #     else:
    #         counter[baseline_pkt_alerts[key]["rule"]]=1

    # print("\n\n")
    # print(counter)

    # counter = {}
    # for key in set(experiment_pkt_alerts.keys()) - set(baseline_pkt_alerts.keys()):
    #     print(key, experiment_pkt_alerts[key]["rule"], experiment_pkt_alerts[key]["proto"], experiment_pkt_alerts[key]["src_ap"], experiment_pkt_alerts[key]["dst_ap"])
    #     if experiment_pkt_alerts[key]["rule"] in counter:
    #         counter[experiment_pkt_alerts[key]["rule"]]+=1
    #     else:
    #         counter[experiment_pkt_alerts[key]["rule"]]=1

    # print("\n\n")
    # print(counter)

    #os.remove(suspicious_pkts_pcap)
    return info

# Generate a PCAP with the suspicious pkts to find the alerts
def get_suspicious_pkts_pcap(baseline_pcap, suspicious_pkts, output_folder, file_name):
    suspicious_pkts_pcap = output_folder+file_name+".pcap"
    pcap_writer = PcapWriter(suspicious_pkts_pcap)
    sorted_suspicious_pkts = sorted(suspicious_pkts, key=lambda x: x[0])

    pkt_count = 0
    suspicious_pkts_list_count = 0
    for packet in PcapReader(baseline_pcap):
        if suspicious_pkts_list_count == len(sorted_suspicious_pkts):
            break

        if pkt_count == sorted_suspicious_pkts[suspicious_pkts_list_count][0]:
            pcap_writer.write(packet)
            pcap_writer.flush()
            suspicious_pkts_list_count+=1

        pkt_count+=1
    return suspicious_pkts_pcap

# Run nids with the new suspicious pkts pcap
def nids_with_suspicious_pcap(suspicious_pkts_pcap, sim_config,  output_folder, file_name):
    nids_config_path = sim_config["snort_or_suricata_config_path"]
    ruleset_path = sim_config["ruleset_path"]
    start = time()
    if sim_config["nids_name"] == "snort":
        subprocess.run(["snort", "-c", nids_config_path, "--rule-path",ruleset_path, "-r",suspicious_pkts_pcap, "-l",output_folder, \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
    else:
        subprocess.run(["suricata", "-c", nids_config_path, "-S",ruleset_path, "-r",suspicious_pkts_pcap, "-l",output_folder, \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
    
    nids_processing_time = time() - start
    new_filepath = output_folder+file_name+".txt"
    os.rename(output_folder+"alert_json.txt", new_filepath)
    return new_filepath, nids_processing_time

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_snort_alerts(alerts_filepath):
    pkt_alerts = {}
    flow_alerts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            parsed_line = json.loads(line)

            pkt_key = parsed_line["timestamp"] # + "_" + parsed_line["rule"]                
            if pkt_key not in pkt_alerts:
               pkt_alerts[pkt_key] = parsed_line

            flow_key = parsed_line["proto"] + "_" + parsed_line["src_ap"] + "_" + parsed_line["dst_ap"]
            if flow_key not in flow_alerts:
               flow_alerts[flow_key] = parsed_line
               
    return pkt_alerts, flow_alerts



def parse_suricata_alerts(alerts_filepath):
    pkt_alerts = {}
    flow_alerts = {}
    # with open(alerts_filepath, 'r') as file:
    #     for line in file.readlines():
    #         parsed_line = json.loads(line)

    #         pkt_key = parsed_line["timestamp"] # + "_" + parsed_line["rule"]                
    #         if pkt_key not in pkt_alerts:
    #            pkt_alerts[pkt_key] = parsed_line

    #         flow_key = parsed_line["proto"] + "_" + parsed_line["src_ap"] + "_" + parsed_line["dst_ap"]
    #         if flow_key not in flow_alerts:
    #            flow_alerts[flow_key] = parsed_line
               
    return pkt_alerts, flow_alerts
