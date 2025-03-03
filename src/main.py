from time import time
import sys
import json
import os

from nids_parser.config_parser import NIDSConfiguration
from nids_parser.rules_to_match import convert_rules_to_matches
from simulator.simulation import pre_filtering_simulation, flow_sampling_simulation

def main(simulation_config_path, sim_results_folder):
    with open(simulation_config_path, 'r') as f:
        simulation_config = json.load(f)

    info = {}
    start = time()
    if simulation_config["type"] == "pre_filtering":
        start = time()
        nids_config = NIDSConfiguration(configuration_dir=simulation_config["ipvars_config_path"])
        print("*" * 80)
        print("*" * 26 + " NIDS RULES PARSING STAGE " + "*" * 27+ "\n\n")
        matches, info["number_of_rules"] = convert_rules_to_matches(simulation_config, nids_config)
        info["time_to_process_rules"] = time()-start
        info["payload_size_MB"] = calculate_payload_size(matches)
        
        print("PRE-FILTERING SIMULATION")
        output_folder = sim_results_folder+"pre_filtering_"+simulation_config["scenario"]+"/"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        info = pre_filtering_simulation(simulation_config, matches, output_folder, info)
    elif simulation_config["type"] == "flow_sampling":
        print("FLOW SAMPLING SIMULATION")
        output_folder = sim_results_folder+"flow_sampling_"+str(simulation_config["flow_count_threshold"])+"_"+str(simulation_config["time_threshold"])+"/"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        info = flow_sampling_simulation(simulation_config, output_folder)
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
            if type(content[2]) is str:
                match_size+=sys.getsizeof(content[2])
            else:
                for modifier in content[2]:
                    match_size+=sys.getsizeof(modifier)

        return match_size


    total_payload_size = 0
    for protocol_key in matches:
        for header_group in matches[protocol_key]:
            for match in matches[protocol_key][header_group]:
                if "content" in match.payload_fields:
                    for content in match.payload_fields["content"]:
                        total_payload_size+=get_size(content)

                if "pcre" in match.payload_fields:
                    for pcre in match.payload_fields["pcre"]:
                        total_payload_size+=get_size(pcre)


    return total_payload_size/1000000


if __name__ == '__main__':
    simulation_config_file = sys.argv[1]
    sim_results_folder = "simulation_results/"
    
    main(simulation_config_file, sim_results_folder)