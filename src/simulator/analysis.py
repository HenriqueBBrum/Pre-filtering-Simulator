import os
import re
import json
import subprocess
from time import time
from scapy.utils import PcapReader, PcapWriter 

def compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info): 
    suspicious_pkts_alert_file, nids_processing_time = nids_with_suspicious_pcap(sim_config, suspicious_pkts, current_trace, output_folder) # WHAT IF THERE IS NO SUSPCIIOUS PACKETS?
    info[current_trace]["nids_processing_time"] = nids_processing_time
    if sim_config["nids_name"] == "snort":
        baseline_signatures, baseline_flow_signatures = parse_snort_alerts(sim_config["baseline_alerts_path"]+current_trace+".txt") # Baseline alerts
        experiment_signatures, experiment_flow_signatures = parse_snort_alerts(suspicious_pkts_alert_file)
    else: 
        baseline_signatures, baseline_flow_signatures = parse_suricata_alerts(sim_config["baseline_alerts_path"]+current_trace+".log") # Baseline alerts
        experiment_signatures, experiment_flow_signatures = parse_suricata_alerts(suspicious_pkts_alert_file)

    missed_signatures = 0
    aditional_signatures = 0
    for key in baseline_signatures.keys() | experiment_signatures.keys():
        base = baseline_signatures.get(key, 0)
        exp = experiment_signatures.get(key, 0)
        if base-exp>0:
            missed_signatures+=base-exp
        elif base-exp:
            aditional_signatures+=exp-base

    # Alert metrics for individual packets
    info[current_trace]["baseline_signatures"] = sum(baseline_signatures.values())
    info[current_trace]["experiment_signatures"] =  sum(experiment_signatures.values())
    info[current_trace]["signatures_true_positive"] = sum(baseline_signatures.values()) - missed_signatures
    info[current_trace]["signatures_false_negative"] = missed_signatures
    info[current_trace]["signatures_false_positive"] = aditional_signatures

    # counter = {}
    # for key in set(baseline_flow_signatures.keys()) - set(experiment_flow_signatures.keys()):
    #     print(key)
        # if baseline_pkt_alerts[key]["rule"] in counter:
        #     counter[baseline_pkt_alerts[key]["rule"]]+=1
        # else:
        #     counter[baseline_pkt_alerts[key]["rule"]]=1

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
    return info

def nids_with_suspicious_pcap(sim_config, suspicious_pkts, current_trace, output_folder):
    suspicious_pkts_pcap = output_folder+current_trace+".pcap"
    pcap_writer = PcapWriter(suspicious_pkts_pcap, 1)
    sorted_suspicious_pkts = sorted(suspicious_pkts, key=lambda x: x[0])

    pkt_count = 0
    suspicious_pkts_list_count = 0
    for packet in PcapReader(sim_config["pcaps_path"]+current_trace+".pcap"):
        if suspicious_pkts_list_count == len(sorted_suspicious_pkts):
            break

        if pkt_count == sorted_suspicious_pkts[suspicious_pkts_list_count][0]:
            pcap_writer.write(packet)
            pcap_writer.flush()
            suspicious_pkts_list_count+=1

        pkt_count+=1

    start = time()
    if sim_config["nids_name"] == "snort":
        subprocess.run(["snort", "-c", sim_config["nids_config_path"], "--rule-path", sim_config["ruleset_path"], "-r",suspicious_pkts_pcap, "-l",output_folder, \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
        
        new_filepath = output_folder+current_trace+".txt"
        os.rename(output_folder+"alert_json.txt", new_filepath)
    else:
        subprocess.run(["suricata", "-c", sim_config["nids_config_path"], "-S", sim_config["ruleset_path"], "-r",suspicious_pkts_pcap, "-l",output_folder], stdout=subprocess.DEVNULL)
        new_filepath = output_folder+current_trace+".log"
        os.rename(output_folder+"fast.log", new_filepath)

    # os.remove(suspicious_pkts_pcap)
    return new_filepath, time() - start

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_snort_alerts(alerts_filepath):
    signatures = {}
    flow_signatures = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            parsed_line = json.loads(line)

            signature = parsed_line["rule"].split(':')[1]
            if signature not in signatures:
                signatures[signature]=1
            else:
                signatures[signature]+=1

            flow_signature = signature+ "_" +parsed_line["proto"] + "_" + parsed_line["src_ap"] + "_" + parsed_line["dst_ap"]
            if flow_signature not in flow_signatures:
                flow_signatures[flow_signature] = 1
            else:
                flow_signatures[flow_signature]+=1
               
    return signatures, flow_signatures

def parse_suricata_alerts(alerts_filepath):
    signatures = {}
    flow_signatures = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            l = line.strip()
            signature = re.search("\[\d*:\d*:\d*]", l).group(0).split(':')[1]
            flow = re.search("{.*$", l).group(0).replace("-> ", "").replace("<> ", "")
            flow = flow.replace(" ", "_").replace("{", "").replace("}", "")

            if signature not in signatures:
                signatures[signature]=1
            else:
                signatures[signature]+=1

            flow_signature = signature+ "_" +flow
            if flow_signature not in flow_signatures:
                flow_signatures[flow_signature] = 1
            else:
                flow_signatures[flow_signature]+=1
               
    return signatures, flow_signatures