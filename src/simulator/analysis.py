import os
import json
import subprocess
from time import time
from scapy.utils import PcapReader, PcapWriter 

def compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info): 
    baseline_pcap = sim_config["pcaps_path"]+current_trace+".pcap"

    suspicious_pkts_pcap = get_suspicious_pkts_pcap(baseline_pcap, suspicious_pkts, output_folder, current_trace)
    suspicious_pkts_alert_file, snort_processing_time = snort_with_suspicious_pcap(suspicious_pkts_pcap, sim_config["snort_config_file"], sim_config["ruleset_path"], output_folder, current_trace)
    info[current_trace]["snort_processing_time"] = snort_processing_time

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

# Run snort with the new suspicious pkts pcap
def snort_with_suspicious_pcap(suspicious_pkts_pcap, snort_config_path, ruleset_path,  output_folder, file_name):
    start = time()
    subprocess.run(["snort", "-c", snort_config_path, "--rule-path",ruleset_path, "-r",suspicious_pkts_pcap, "-l",output_folder, \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
    
    snort_processing_time = time() - start
    new_filepath = output_folder+file_name+".txt"
    os.rename(output_folder+"alert_json.txt", new_filepath)
    return new_filepath, snort_processing_time

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_alerts(alerts_filepath):
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
