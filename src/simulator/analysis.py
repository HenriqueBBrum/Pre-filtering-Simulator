import os
import re
import json
import subprocess
from time import time
from scapy.utils import PcapReader, PcapWriter 

# Compare the alert from an experiment with the baseline alerts
def compare_to_baseline(sim_config, suspicious_pkts, current_trace, output_folder, info): 
    suspicious_pkts_alert_file, nids_processing_time = nids_with_suspicious_pcap(sim_config, suspicious_pkts, current_trace, output_folder) # WHAT IF THERE IS NO SUSPCIIOUS PACKETS?
    info[current_trace]["nids_processing_time"] = nids_processing_time
    baseline_signatures = parse_snort_alerts(sim_config["baseline_alerts_path"]+current_trace+".txt", sim_config["nids_name"]) # Baseline alerts
    experiment_signatures = parse_snort_alerts(suspicious_pkts_alert_file, sim_config["nids_name"])
      
    missed_signatures = 0
    aditional_signatures = 0
    for key in baseline_signatures.keys() | experiment_signatures.keys():
        base = baseline_signatures.get(key, 0)
        exp = experiment_signatures.get(key, 0)
        if base-exp>0:
            missed_signatures+=base-exp
            # print(key, base-exp)
        elif base-exp:
            aditional_signatures+=exp-base

    # Alert metrics for individual packets
    info[current_trace]["baseline_signatures"] = sum(baseline_signatures.values())
    info[current_trace]["experiment_signatures"] =  sum(experiment_signatures.values())
    info[current_trace]["signatures_true_positive"] = sum(baseline_signatures.values()) - missed_signatures
    info[current_trace]["signatures_false_negative"] = missed_signatures
    info[current_trace]["signatures_false_positive"] = aditional_signatures

    return info

# Run Snort or Suricata with the final pcap after pre-filtering or packet sampling
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

    os.remove(suspicious_pkts_pcap)
    return new_filepath, time() - start

# Parses an alert file and calculate the amount of detected signatures. 
def parse_alerts(alerts_filepath, nids_name):
    signatures = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            if nids_name == "snort"
                parsed_line = json.loads(line)
                signature = parsed_line["rule"].split(':')[1]
            elif nids_name == "suricata":
                l = line.strip()
                signature = re.search("\[\d*:\d*:\d*]", l).group(0).split(':')[1]

            if signature not in signatures:
                signatures[signature]=1
            else:
                signatures[signature]+=1
      
    return signatures
