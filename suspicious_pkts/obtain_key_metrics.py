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
        information[scenario_folder] = get_resource_usage_info(scenario_results_folder+"log.txt")
        for file in os.listdir(scenario_results_folder):
            print(file)
            if "log" in file or "txt" not in file:
                continue

            suspicious_pkts_pcap = generate_suspicious_pkts_pcap(original_pcaps_folder, scenario_results_folder, file)
            suspicious_pkts_alert_file = snort_with_suspicious_pcap(suspicious_pkts_pcap, alerts_output_folder, file)
            original_pcap_alerts = parse_alerts(original_pcaps_folder+"/alerts_registered/"+file)
            reduced_pcap_alerts = parse_alerts(suspicious_pkts_alert_file)

            file_name = file.split(".")[0]
            information[scenario_folder][file_name]["alerts_baseline"] = len(original_pcap_alerts)
            information[scenario_folder][file_name]["alerts_experiment"] =  len(reduced_pcap_alerts)
            information[scenario_folder][file_name]["TP"] = len(set(original_pcap_alerts.keys()) & set(reduced_pcap_alerts.keys()))
            information[scenario_folder][file_name]["FN"] = len(set(original_pcap_alerts.keys()) - set(reduced_pcap_alerts.keys()))
            information[scenario_folder][file_name]["FP"] = len(set(reduced_pcap_alerts.keys()) - set(original_pcap_alerts.keys()))
            # counter = {}
            # for key in set(original_pcap_alerts.keys()) - set(reduced_pcap_alerts.keys()):
            #     print(key, original_pcap_alerts[key])
            #     if original_pcap_alerts[key][0] in counter:
            #         counter[original_pcap_alerts[key][0]]+=1
            #     else:
            #         counter[original_pcap_alerts[key][0]]=1

            # print("\n\n")
            # print(counter)

            # counter = {}
            # for key in set(reduced_pcap_alerts.keys()) - set(original_pcap_alerts.keys()):
            #     print(key, reduced_pcap_alerts[key])
            #     if reduced_pcap_alerts[key][0] in counter:
            #         counter[reduced_pcap_alerts[key][0]]+=1
            #     else:
            #         counter[reduced_pcap_alerts[key][0]]=1

            # print("\n\n")
            # print(counter)

            #os.remove(suspicious_pkts_pcap)

        with open(alerts_output_folder + "analysis.txt", 'w') as f:
            json.dump(information[scenario_folder] , f, ensure_ascii=False, indent=4)

# Reads the log file from a simulation folder and saves the main info in a dict
def get_resource_usage_info(log_file):
    resource_info = {}
    with open(log_file, 'r') as log:
        current_pcap_name = ""
        for line in log.readlines():
            if not current_pcap_name:
                if "Total deduped rules: " in line:
                    resource_info["amount_rules"] = int(re.search("\d+\.?\d*", line).group(0))

                if "Header size" in line:
                    resource_info["header_size"] = float(re.search("\d+\.?\d*", line).group(0)) # in MB

                if "Payload size" in line:
                    resource_info["payload_size"] = float(re.search("\d+\.?\d*", line).group(0)) # in MB

            if "Starting" in line:
                current_pcap_name = re.search("\/pcaps\/(.*)\.", line).group(1)
                resource_info[current_pcap_name] = {}

            if "Time to process" in line:
                execution_info = re.findall(r"\d+\.*\d*", line)
                resource_info[current_pcap_name]["amount_packets"] = int(execution_info[0])
                resource_info[current_pcap_name]["time_to_process"] = float(execution_info[2])
            if "Suspicious packets" in line:
                resource_info[current_pcap_name]["suspicious_packets"] = int(re.search(r"\d+\.*\d*", line).group(0))

    return resource_info
 
# Based on the list of suspicious packets IDs (packets position in the original PCAP) generate a pcap
def generate_suspicious_pkts_pcap(original_pcaps_folder, scenario_folder, file):
    print(scenario_folder, file)
    suspicious_pkts_list = []
    with open(scenario_folder+file, 'r') as suspicious_pkts:
        suspicious_pkts_list = [int(line[:-1]) if line[-1] == "\n" else int(line) for line in suspicious_pkts.readlines()]

    suspicious_pkts_output_pcap = scenario_folder+file.split(".")[0]+".pcap"
    original_pcap_file = original_pcaps_folder+"/pcaps/"+file.split(".")[0]+".pcap"

    pcap_writer = PcapWriter(suspicious_pkts_output_pcap)

    pkt_count = 0
    suspicious_pkts_list_count = 0
    for packet in PcapReader(original_pcap_file):
        if suspicious_pkts_list_count == len(suspicious_pkts_list):
            break

        if pkt_count == suspicious_pkts_list[suspicious_pkts_list_count]:
            pcap_writer.write(packet)
            pcap_writer.flush()
            suspicious_pkts_list_count+=1

        pkt_count+=1
    
    return suspicious_pkts_output_pcap

# Run snort with the new suspicious pkts pcap
def snort_with_suspicious_pcap(suspicious_pkts_pcap, alerts_output_folder, file):
    print(rules_path)
    subprocess.run(["snort", "-c", config_path, "--rule-path",rules_path, "-r",suspicious_pkts_pcap, "-l",alerts_output_folder, \
                    "-A","alert_json",  "--lua","alert_json = {file = true}"], stdout=subprocess.DEVNULL)
    new_filepath = alerts_output_folder+file
   
    os.rename(alerts_output_folder+"alert_json.txt", new_filepath)
    return new_filepath

# Parses an alert file and keeps only one entry for each packet (based on the 'pkt_num' entry in the alert). 
# Saves the 'pkt_len', 'dir', 'src_ap'and 'dst_ap' fields as an identifier to compare with other alert files
def parse_alerts(alerts_filepath):
    alerted_pkts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            parsed_line = json.loads(line)
            if parsed_line["timestamp"] not in alerted_pkts:
               alerted_pkts[parsed_line["timestamp"]] = [parsed_line["rule"]]
            else:
               alerted_pkts[parsed_line["timestamp"]].append(parsed_line["rule"])
               
    return alerted_pkts




if __name__ == '__main__':
    scenario_to_analyze = None
    if len(sys.argv) > 1:
        scenario_to_analyze = sys.argv[1]

    main(scenario_to_analyze)