from time import time
import sys
import json

from snort_parser.config_parser import SnortConfiguration
from snort_parser.parsing_rules import parse_rules
from simulator.simulation import pre_filtering_simulation, flow_sampling_simulation

def main(simulation_config_path, sim_results_folder):
    with open(simulation_config_path, 'r') as f:
        simulation_config = json.load(f)

    start = time()
    if simulation_config["type"] == "pre_filtering":
        config = SnortConfiguration(snort_version=2, configuration_dir=simulation_config["snort_config_path"])
        print("*" * 80)
        print("*" * 26 + " SNORT RULES PARSING STAGE " + "*" * 27+ "\n\n")
        final_rules = parse_rules(config, simulation_config["scenario"], simulation_config["ruleset_path"])

        print(final_rules.keys())        
        print("PRE-FILTERING SIMULATION")
        pre_filtering_simulation(simulation_config, final_rules, {}, sim_results_folder)
    elif simulation_config["type"] == "flow_sampling":
        print("FLOW SAMPLING SIMULATION")
        flow_sampling_simulation(simulation_config, sim_results_folder)
    else:
        print("Wrong simulation type")
        exit(1)

    print("Simulation time: ", time() - start)


if __name__ == '__main__':
    simulation_config_file = sys.argv[1]
    sim_results_folder = "simulation_results/"
    main(simulation_config_file, sim_results_folder)