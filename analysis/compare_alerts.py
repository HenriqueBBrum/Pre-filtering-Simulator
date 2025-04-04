import json
import os
import re
import sys

import pprint
import argparse

def main(baseline_folder, exps_folder, nids_name):
    missed_signatures_counter = {}
    for alert_file in os.listdir(exps_folder):  
        if ".log" not in alert_file:
            continue

        baseline_signatures = parse_alerts(baseline_folder+alert_file, nids_name) # Baseline alerts
        experiment_signatures = parse_alerts(exps_folder+alert_file, nids_name)
        
        missed_signatures = 0
        aditional_signatures = 0
        print(alert_file)
        for key in baseline_signatures.keys() | experiment_signatures.keys():
            if key not in missed_signatures_counter:
                missed_signatures_counter[key] = 0

            base = baseline_signatures.get(key, 0)
            exp = experiment_signatures.get(key, 0)
            if base-exp>0:
                print("Missed signatures for", key, ": ", base-exp)
                missed_signatures+=base-exp
                missed_signatures_counter[key]+=base-exp
            elif base-exp:
                aditional_signatures+=exp-base


        print("end of trace, ", alert_file)
    pprint.pprint(missed_signatures_counter, sort_dicts=True)

# Parses an alert file and calculate the amount of detected signatures. 
def parse_alerts(alerts_filepath, nids_name):
    signatures = {}
    with open(alerts_filepath, 'r') as file:
        for line in file.readlines():
            if nids_name == "snort":
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



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Compare alerts between baseline and experiment folders.")
    parser.add_argument("baseline_folder", help="Path to the baseline folder containing alert files.")
    parser.add_argument("exps_folder", help="Path to the experiment folder containing alert files.")
    parser.add_argument("nids_name", choices=["snort", "suricata"], help="Name of the NIDS (snort or suricata).")
    args = parser.parse_args()

    main(args.baseline_folder, args.exps_folder, args.nids_name)