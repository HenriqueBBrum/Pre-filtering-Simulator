import sys
import json
import os
from time import time

from nids_parser.config_parser import NIDSConfiguration
from nids_parser.rules_to_matches import convert_rules_to_matches
from simulator.pre_filtering_simulator import pre_filtering_simulation 
from simulator.flow_sampling_simulator import flow_sampling_simulation

OUTPUT_FOLDER = "simulation_results/"

def generate_simulation(simulation_type, nids_name):
    simulation_config = {}
    simulation_config["nids_name"] = nids_name
    simulation_config["pcaps_path"] = "/home/hbeckerbrum/simulator_results/with_scapy/split_pcaps/pcaps/"

    simulation_config["baseline_alerts_path"] = "/home/hbeckerbrum/simulator_results/with_scapy/alerts/split_pcap/"
    if nids_name == "snort":
        simulation_config["nids_config_path"] = "etc/nids_configuration/snort/snort.lua"
        simulation_config["ruleset_path"] = "etc/rules/snort3-registered/"
    else:
        simulation_config["nids_config_path"] = "etc/nids_configuration/suricata/suricata.yaml"
        simulation_config["ruleset_path"] = "etc/rules/suricata-emerging/emerging-all.rules"

    if simulation_type == "pre_filtering":
        simulation_config["ipvars_config_path"] = "etc/nids_configuration/"
        simulation_config["scenario"] = "testing"

    return simulation_config

def main(simulation_type, nids_name):
    simulation_config = generate_simulation(simulation_type, nids_name)

    info = {}
    start = time()
    if simulation_type:
        start = time()
        nids_config = NIDSConfiguration(simulation_config["ipvars_config_path"])
        print("*" * 80)
        print("*" * 26 + " NIDS RULES PARSING STAGE " + "*" * 27+ "\n\n")
        matches, info["number_of_rules"] = convert_rules_to_matches(simulation_config, nids_config)
        info["time_to_process_rules"] = time()-start
        info["payload_size_MB"] = calculate_payload_size(matches)
        
        print("PRE-FILTERING SIMULATION")
        output_folder = OUTPUT_FOLDER+"pre_filtering_"+nids_name+"_"+simulation_config["scenario"]+"/"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        # pre_filtering_simulation(simulation_config, matches, output_folder, info)
    elif simulation_config["type"] == "flow_sampling":
        for n in [5, 10, 25, 50, 100]:
            for t in [5, 10, 25, 50, 100]:
                print("FLOW SAMPLING SIMULATION")
                output_folder = OUTPUT_FOLDER+"flow_sampling_"+simulation_config["nids_name"]+"_"+str(n)+"_"+str(t)+"/"
                if not os.path.exists(output_folder):
                    os.makedirs(output_folder)

                flow_sampling_simulation(simulation_config, output_folder, n, t, info)

    else:
        print("Wrong simulation type")
        exit(1)

    json.dump(info, sys.stdout, indent=4)

    info["total_execution_time"] = time() - start
    with open(output_folder + "analysis.json", 'a') as f:
        json.dump(info , f, ensure_ascii=False, indent=4)



# Calculates the amount of bytes required by python to store the rules
def calculate_payload_size(matches):

    def get_size(content):
        match_size = 0
        match_size+=sys.getsizeof(content[1]) # Content string
        if content[2]: # Modifiers
            if isinstance(content[2], list):
                for modifier in content[2]:
                    match_size+=sys.getsizeof(modifier)
            else:
                match_size+=sys.getsizeof(content[2])


        return match_size


    total_payload_size = 0
    for protocol_key in matches:
        for header_group in matches[protocol_key]:
            for match in matches[protocol_key][header_group]:
                if "content_pcre" in match.payload_fields:
                    for content in match.payload_fields["content_pcre"]:
                        total_payload_size+=get_size(content)


    return total_payload_size/1000000


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])