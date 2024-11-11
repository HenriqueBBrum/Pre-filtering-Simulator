from os import listdir,path,remove
from scapy.all import PcapReader, PcapWriter
import re
import subprocess

original_pcaps_folder = "../selected_pcaps/"
results_folder = "./"


def main():
    information = {}
    for folder in listdir(results_folder):
        if "full" not in folder:
            continue
        # Get the amount of rules and memory used 
        if not path.isdir(folder):
            continue

        scenario_folder = results_folder + folder + "/registered/"
        information[folder] = {}
        print(scenario_folder)
        for file in listdir(scenario_folder):
            print(file)
            if file == "log.txt":
                information[folder]["resources_used"] = get_resource_usage_info(scenario_folder+file)
                print(information[folder])
            else:
                suspicious_pkts_pcap = generate_suspicous_pkts_pcap(original_pcaps_folder, scenario_folder, file)
                alerts_file = snort_with_suspicious_pcap(suspicious_pkts_pcap, scenario_folder)
                #confusion_matrix = get_alerts_confusion_matrix(original_pcaps_folder, alerts_file)
                input()
                remove(suspicious_pkts_pcap)
                remove(alerts_file)
                #print(confusion_matrix)
            # Run snort and get the alerts from the suspicious packets
            # Compare the alerts to the baseline and check the number of false positives and false negatives
        break
    # Save data to an easy to read an plot file


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
def generate_suspicous_pkts_pcap(original_pcaps_folder, scenario_folder, file):
    suspicious_pkts_list = []
    with open(scenario_folder+file) as suspicious_pkts:
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

def snort_with_suspicious_pcap(suspicious_pkts_pcap, scenario_folder):
    rules_path = "../etc/rules/snortrules-snapshot-3000/"
    config_path = "../etc/configuration/snort.lua"
    subprocess.run(["snort", "-c", config_path, "--rule-path",rules_path, "-r",suspicious_pkts_pcap, "-l",scenario_folder, "-A","alert_json",  "--lua","alert_json = {file = true}"])
    return scenario_folder+"alerts_json.txt"

def get_alerts_confusion_matrix(original_pcaps_folder, experiments_alerts):

    pass


if __name__ == '__main__':
    main()