import os
import re
import json
import subprocess
import argparse
from time import time

from scapy.utils import PcapReader, PcapWriter 

# Compare the alerts from an experiment with the baseline alerts
def compare_to_baseline(sim_config, current_trace, suspicious_pkts, info): 
    suspicious_pkts_alert_file, nids_processing_time = nids_with_suspicious_pcap(sim_config, current_trace, suspicious_pkts) # WHAT IF THERE IS NO SUSPCIIOUS PACKETS?
    info[current_trace]["nids_processing_time"] = nids_processing_time
    
    baseline_signatures, baseline_signatures_flow = parse_alerts(sim_config["baseline_alerts_path"]+current_trace+".log", sim_config["nids_name"]) # Baseline alerts
    experiment_signatures, experiment_signatures_flow = parse_alerts(suspicious_pkts_alert_file, sim_config["nids_name"])

    missed_signatures = 0
    aditional_signatures = 0
    for key in baseline_signatures.keys() | experiment_signatures.keys():
        base = baseline_signatures.get(key, 0)
        exp = experiment_signatures.get(key, 0)
        if base-exp>0:
            missed_signatures+=base-exp
        elif base-exp:
            aditional_signatures+=exp-base

    info[current_trace]["baseline_signatures"] = sum(baseline_signatures.values())
    info[current_trace]["experiment_signatures"] =  sum(experiment_signatures.values())
    info[current_trace]["signatures_true_positive"] = sum(baseline_signatures.values()) - missed_signatures
    info[current_trace]["signatures_false_negative"] = missed_signatures
    info[current_trace]["signatures_false_positive"] = aditional_signatures

    missed_signatures_flow = 0
    aditional_signatures_flow = 0
    for key in baseline_signatures_flow.keys() | experiment_signatures_flow.keys():
        base = baseline_signatures_flow.get(key, 0)
        exp = experiment_signatures_flow.get(key, 0)
        if base-exp==1:
            missed_signatures_flow+=1
        elif base-exp==-1:
            aditional_signatures_flow+=1

    info[current_trace]["baseline_signatures_flow"] = sum(baseline_signatures_flow.values())
    info[current_trace]["experiment_signatures_flow"] =  sum(experiment_signatures_flow.values())
    info[current_trace]["signatures_flow_true_positive"] = sum(baseline_signatures_flow.values()) - missed_signatures_flow
    info[current_trace]["signatures_flow_false_negative"] = missed_signatures_flow
    info[current_trace]["signatures_flow_false_positive"] = aditional_signatures_flow

# Run Snort or Suricata with the final pcap after pre-filtering or packet sampling
def nids_with_suspicious_pcap(sim_config, current_trace, suspicious_pkts):
    suspicious_pkts_pcap = sim_config["output_folder"]+current_trace+".pcap"
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
        subprocess.run(["snort", "-c", sim_config["nids_config_path"], "--rule-path", sim_config["ruleset_path"], "-r",suspicious_pkts_pcap, "-l",sim_config["output_folder"], \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
        
        new_filepath = sim_config["output_folder"]+current_trace+".log"
        os.rename(sim_config["output_folder"]+"alert_json.txt", new_filepath)
    else:
        subprocess.run(["suricata", "-c", sim_config["nids_config_path"], "-S", sim_config["ruleset_path"], "-r",suspicious_pkts_pcap, "-l",sim_config["output_folder"]], stdout=subprocess.DEVNULL)
        new_filepath = sim_config["output_folder"]+current_trace+".log"
        os.rename(sim_config["output_folder"]+"fast.log", new_filepath)

    os.remove(suspicious_pkts_pcap)
    return new_filepath, time() - start

# Parses an alert file and calculate the amount of detected signatures. 
def parse_alerts(alerts_filepath, nids_name):
    signatures = {}
    flow_signatures = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            if nids_name == "snort":
                parsed_line = json.loads(line)
                signature = parsed_line["rule"].split(':')[1]
                flow_signature = parsed_line["proto"]+" - "+parsed_line["src_ap"]+" - "+parsed_line["dst_ap"]+" - "+signature
            elif nids_name == "suricata":
                l = line.strip()
                signature = re.search("\[\d*:\d*:\d*]", l).group(0).split(':')[1]   
                proto = re.search(r"\{([a-zA-Z]+)\}", l).group(1)
                src_ap, dst_ap = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+) -> (\d+\.\d+\.\d+\.\d+:\d+)", l).groups()
                flow_signature = proto+" - "+src_ap+" - "+dst_ap+" - "+signature

            if signature not in signatures:
                signatures[signature]=1
            else:
                signatures[signature]+=1

            if flow_signature not in flow_signatures:
                flow_signatures[flow_signature]=1
      
    return signatures, flow_signatures


# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description="Analyze the differences in alerts between the baseline and the experiment.")
#     parser.add_argument("dataset_name", choices=["CICIDS2017", "CICIoT2023"], help="Dataset name (CICIDS2017 or CICIoT2023).")
#     parser.add_argument("target_nids", choices=["snort", "suricata"], help="Target NIDS (snort or suricata).")

#     args = parser.parse_args()
#     results_folder = f"/home/hbeckerbrum/Pre-filtering-Simulator/simulation_results/"
#     baseline_folder = "/home/hbeckerbrum/Pre-filtering-Simulator/etc/"
#     for folder in os.listdir(f"{results_folder}{args.dataset_name}/{args.target_nids}/"):
#         if not os.path.isdir(os.path.join(f"{results_folder}{args.dataset_name}/{args.target_nids}/", folder)):
#             continue

#         print(f"Folder: {folder}")
#         analysis_file = os.path.join(f"{results_folder}{args.dataset_name}/{args.target_nids}/", folder, "analysis.json")

#         if os.path.exists(analysis_file):
#             with open(analysis_file, "r") as f:
#                 analysis_data = json.load(f)
#         else:
#             analysis_data = {}
#         for alert_file in os.listdir(os.path.join(f"{results_folder}{args.dataset_name}/{args.target_nids}/", folder)):
#             if not alert_file.endswith(".log"):
#                 continue

#             experiments_alerts = os.path.join(f"{results_folder}{args.dataset_name}/{args.target_nids}/", folder, alert_file)
#             print(f"Experiment: {alert_file}")

#             baseline_alerts = os.path.join(f"{baseline_folder}{args.dataset_name}/alerts/{args.target_nids}", alert_file)
#             baseline_signatures, baseline_signatures_flow = parse_alerts(baseline_alerts, args.target_nids) # Baseline alerts
#             experiment_signatures, experiment_signatures_flow = parse_alerts(experiments_alerts, args.target_nids)

#             missed_signatures = 0
#             aditional_signatures = 0
#             for key in baseline_signatures.keys() | experiment_signatures.keys():
#                 base = baseline_signatures.get(key, 0)
#                 exp = experiment_signatures.get(key, 0)
#                 if base-exp>0:
#                     missed_signatures+=base-exp
#                 elif base-exp:
#                     aditional_signatures+=exp-base

#             missed_flow_signatures = 0
#             aditional_flow_signatures = 0
#             for key in baseline_signatures_flow.keys() | experiment_signatures_flow.keys():
#                 base = baseline_signatures_flow.get(key, 0)
#                 exp = experiment_signatures_flow.get(key, 0)
#                 if base-exp==1:
#                     missed_flow_signatures+=1
#                 elif base-exp==-1:
#                     aditional_flow_signatures+=1

#             alert_file_key = alert_file.replace(".log", "")
#             new_data = {
#                 "baseline_signatures": sum(baseline_signatures.values()),
#                 "experiment_signatures": sum(experiment_signatures.values()),
#                 "signatures_true_positive": sum(baseline_signatures.values()) - missed_signatures,
#                 "signatures_false_negative": missed_signatures,
#                 "signatures_false_positive": aditional_signatures,
#                 "baseline_signatures_flow": sum(baseline_signatures_flow.values()),
#                 "experiment_signatures_flow": sum(experiment_signatures_flow.values()),
#                 "signatures_flow_true_positive": sum(baseline_signatures_flow.values()) - missed_flow_signatures,
#                 "signatures_flow_false_negative": missed_flow_signatures,
#                 "signatures_flow_false_positive": aditional_flow_signatures,
#             }

#             analysis_data[alert_file_key].update(new_data)
            

#             with open(analysis_file, "w") as f:
#                 json.dump(analysis_data , f, indent=4)





    
