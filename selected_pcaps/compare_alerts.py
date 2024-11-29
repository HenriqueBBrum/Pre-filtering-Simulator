import os
import re
import sys
import json
import subprocess
from scapy.all import PcapReader, PcapWriter

original_pcaps_folder = "../selected_pcaps/"
simulation_results_folder = "./"

rules_path = "../etc/rules/snort3-registered/"
config_path = "../etc/configuration/snort.lua"

def main(scenario_to_analyze):
    information = {}
    if scenario_to_analyze:
        list_of_scenarios = [scenario_to_analyze]
    else:
        list_of_scenarios = os.listdir(simulation_results_folder)

    for scenario_folder in list_of_scenarios:
        if not os.path.isdir(scenario_folder):
            continue

        scenario_results_folder = simulation_results_folder + scenario_folder + "/registered/" 
        if not os.path.exists(scenario_results_folder):
            os.makedirs(scenario_results_folder)

        alerts_output_folder = simulation_results_folder + scenario_folder + "/alerts_registered/"
        if not os.path.exists(alerts_output_folder):
            os.makedirs(alerts_output_folder)

        information[scenario_folder] = {}
        for file in os.listdir(scenario_results_folder):
            print(file)
            if "log" in file or "txt" not in file:
                continue

            file_name = file.split(".")[0]
            information[scenario_folder][file_name]["alerts_baseline"] = len(original_pcap_alerts)
            information[scenario_folder][file_name]["alerts_experiment"] =  len(reduced_pcap_alerts)
            information[scenario_folder][file_name]["TP"] = len(set(original_pcap_alerts.keys()) & set(reduced_pcap_alerts.keys()))
            information[scenario_folder][file_name]["FN"] = len(set(original_pcap_alerts.keys()) - set(reduced_pcap_alerts.keys()))
            information[scenario_folder][file_name]["FP"] = len(set(reduced_pcap_alerts.keys()) - set(original_pcap_alerts.keys()))
            counter = {}
            for key in set(original_pcap_alerts.keys()) - set(reduced_pcap_alerts.keys()):
                timestamp_sid = key.split("_")
                print(timestamp_sid[0], timestamp_sid[1], original_pcap_alerts[key]["proto"], original_pcap_alerts[key]["pkt_gen"])
                if timestamp_sid[1] in counter:
                    counter[timestamp_sid[1]]+=1
                else:
                    counter[timestamp_sid[1]]=1

            print("\n\n")
            print(counter)

            os.remove(suspicious_pkts_pcap)

        with open(alerts_output_folder + "analysis.txt", 'w') as f:
            json.dump(information[scenario_folder] , f, ensure_ascii=False, indent=4)

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_alerts(alerts_filepath):
    alerted_pkts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            parsed_line = json.loads(line)
            key = parsed_line["timestamp"] + "_" + parsed_line["rule"]
            if key not in alerted_pkts:
               alerted_pkts[key] = parsed_line
               
    return alerted_pkts




if __name__ == '__main__':
    scenario_to_analyze = None
    if len(sys.argv) > 1:
        scenario_to_analyze = sys.argv[1]

    main(scenario_to_analyze)