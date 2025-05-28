import json
import os
import re

import pprint
import argparse

import pprint

def main(baseline_folder, exps_folder, nids_name):
    missed_signatures_counter = {}
    for alert_file in os.listdir(exps_folder):  
        if ".log" not in alert_file:
            continue

        baseline_signatures, baseline_flow_singatures = parse_alerts(baseline_folder+alert_file, nids_name) # Baseline alerts
        experiment_signatures, experiment_flow_singatures = parse_alerts(exps_folder+alert_file, nids_name)
        print(alert_file)
        for key in baseline_flow_singatures.keys() | experiment_flow_singatures.keys():
            if key not in experiment_flow_singatures:
                print(key)

        
        print("end of trace, ", alert_file)
    pprint.pprint(missed_signatures_counter, sort_dicts=True)

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



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Compare alerts between baseline and experiment folders.")
    parser.add_argument("baseline_folder", help="Path to the baseline folder containing alert files.")
    parser.add_argument("exps_folder", help="Path to the experiment folder containing alert files.")
    parser.add_argument("nids_name", choices=["snort", "suricata"], help="Name of the NIDS (snort or suricata).")

    args = parser.parse_args()

    main(args.baseline_folder, args.exps_folder, args.nids_name)