from scapy.all import PcapReader, PcapWriter
import os
import re
import subprocess
import json




def main(original_pcaps_folder, simulation_results_folder):
    information = {}
    for scenario_folder in os.listdir(simulation_results_folder):
        if "full" not in scenario_folder:
            continue
        # Get the amount of rules and memory used 
        if not os.path.isdir(scenario_folder):
            continue

        scenario_results_folder = simulation_results_folder + scenario_folder + "/registered/"
        if not os.path.exists(scenario_results_folder):
            os.makedirs(scenario_results_folder)

        alerts_output_folder = simulation_results_folder + scenario_folder + "/alerts/"
        if not os.path.exists(alerts_output_folder):
            os.makedirs(alerts_output_folder)

        information[scenario_folder] = {}
        print(scenario_results_folder)
        for file in os.listdir(scenario_results_folder):
            print(file)
            if file == "log.txt":
                information[scenario_folder]["resources_used"] = get_resource_usage_info(scenario_results_folder+file)
            else:
                suspicious_pkts_pcap = generate_suspicious_pkts_pcap(original_pcaps_folder, scenario_results_folder, file)
                suspicious_pkts_alertfile = snort_with_suspicious_pcap(suspicious_pkts_pcap, scenario_results_folder, file)

                original_pcap_alerts = parse_alerts(original_pcaps_folder+"/alerts_registered/"+file)
                reduced_pcap_alerts = parse_alerts(suspicious_pkts_alertfile)
                print("----------------------------------------")
                print(len(original_pcap_alerts), len(reduced_pcap_alerts))

                c = confusion_matrix(original_pcap_alerts, reduced_pcap_alerts)
                os.remove(suspicious_pkts_pcap)
                os.remove(reduced_pcap_alerts)

        save_info_to_file(alerts_output_folder, information)

        break



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

            if "Starting file processing:" in line:
                current_pcap_name = re.search("\/pcaps\/(.*)\.", line).group(1)
                resource_info[current_pcap_name] = {}

            if "Time to process" in line:
                execution_info = re.findall(r"\d+\.*\d*", line)
                resource_info[current_pcap_name]["amount_packets"] = int(execution_info[0])
                resource_info[current_pcap_name]["time_to_process"] = float(execution_info[2])
            if "Suspicious packets" in line:
                resource_info[current_pcap_name]["suspicious_packets"] = int(re.search(r"\d+\.*\d*", line).group(0))

    return resource_info
 
# Based on a list of packets ids (packets position in the original PCAP) generate a pcap for the suspicious packets
def generate_suspicious_pkts_pcap(original_pcaps_folder, scenario_folder, file):
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

def snort_with_suspicious_pcap(suspicious_pkts_pcap, alerts_output_folder, file):
    rules_path = "../etc/rules/snortrules-snapshot-3000/"
    config_path = "../etc/configuration/snort.lua"
    subprocess.run(["snort", "-c", config_path, "--rule-path",rules_path, "-r",suspicious_pkts_pcap, "-l",alerts_output_folder, "-A","alert_json",  "--lua","alert_json = {file = true}"])
    new_filepath = alerts_output_folder+file.split(".")[0]
    os.rename(alerts_output_folder+"alert_json.txt", new_filepath)
    return new_filepath


def parse_alerts(alerts_filepath):
    alerted_pkts = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
           parsed_line = json.loads(line)
           if parsed_line["pkt_num"] not in alerted_pkts:
               alerted_pkts[parsed_line["pkt_num"]] = str(parsed_line["pkt_len"]) + parsed_line["dir"] + parsed_line["src_ap"] + parsed_line["dst_ap"]
               
    return set(alerted_pkts.values())

def confusion_matrix(baseline_data, experiment_data):
    TP = len(baseline_data & experiment_data)
    FN = len(baseline_data - experiment_data)
    FP = len(experiment_data - baseline_data)
    print("Correct alerts: ", TP)
    print("Alerts only on baseline alerts: ", FN)
    print("Alerts only on suspicious experiment alerts: ", FP)

    return [TP, FP, FN] 


def save_info_to_file(alerts_output_folder, information):
    information_file = alerts_output_folder + "analysis.txt"

if __name__ == '__main__':
    original_pcaps_folder = "../selected_pcaps/"
    simulation_results_folder = "./"
    main(original_pcaps_folder, simulation_results_folder)