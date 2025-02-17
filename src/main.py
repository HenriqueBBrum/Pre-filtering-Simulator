from time import time
import sys
import json
import os

from nids_parser.config_parser import NIDSConfiguration
from nids_parser.parsing_rules import parse_rules, calculate_payload_size
from simulator.simulation import pre_filtering_simulation, flow_sampling_simulation

def main(simulation_config_path, sim_results_folder):
    with open(simulation_config_path, 'r') as f:
        simulation_config = json.load(f)

    info = {}
    start = time()
    if simulation_config["type"] == "pre_filtering":
        start = time()
        config = NIDSConfiguration(configuration_dir=simulation_config["nids_config_path"])
        print("*" * 80)
        print("*" * 26 + " NIDS RULES PARSING STAGE " + "*" * 27+ "\n\n")
        groupped_rules, info["number_of_rules"] = parse_rules(config, simulation_config["scenario"], simulation_config["ruleset_path"])
        info["time_to_process_rules"] = time()-start
        info["payload_size_MB"] = calculate_payload_size(groupped_rules)
        
        print("PRE-FILTERING SIMULATION")
        output_folder = sim_results_folder+"pre_filtering_"+simulation_config["scenario"]+"/"
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        info = pre_filtering_simulation(simulation_config, groupped_rules, info, output_folder)
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


if __name__ == '__main__':
    simulation_config_file = sys.argv[1]
    sim_results_folder = "simulation_results/"
    main(simulation_config_file, sim_results_folder)