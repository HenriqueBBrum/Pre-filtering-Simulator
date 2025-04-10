import sys
import json
import os
from time import time

from nids_parser.config_parser import NIDSConfiguration
from nids_parser.rules_to_matches import convert_rules_to_matches
from simulator.pre_filtering_simulator import pre_filtering_simulation 
from simulator.packet_sampling_simulator import packet_sampling_simulation
import argparse

from scapy.all import TCP
from scapy.packet import bind_layers
from scapy.layers.http import HTTP  

from utils.port_services import file_data_ports, port_to_service_map

OUTPUT_FOLDER = "simulation_results/"

def main(simulation_name, simulation_type, dataset_name, target_nids):
    simulation_config = generate_simulation(simulation_name, dataset_name, target_nids)
    info = {}
    info["type"] = simulation_type
    start = time()
    if simulation_type =="pre_filtering":
        nids_config = NIDSConfiguration(simulation_config["ipvars_config_path"])
        print("*" * 80)
        print("*" * 26 + " NIDS RULES PARSING STAGE " + "*" * 27+ "\n\n")
        matches, no_content_matches, info["number_of_rules"] = convert_rules_to_matches(simulation_config, nids_config)
        for port_group in nids_config.ports:
            if "HTTP" in port_group:
                for port in nids_config.ports[port_group]:
                    bind_layers(TCP, HTTP, sport=int(port[0]))
                    bind_layers(TCP, HTTP, dport=int(port[0]))
                    port_to_service_map[int(port[0])] = "http"
                    file_data_ports.add(int(port[0]))

        info["time_to_process_rules"] = time()-start
        info["payload_size_MB"] = calculate_payload_size(matches)
        
        print("PRE-FILTERING SIMULATION")
        print("Scenario: ", simulation_config["scenario"])
        simulation_config["output_folder"] = os.path.join(OUTPUT_FOLDER, f"{dataset_name}/{target_nids}/pre_filtering_{simulation_name}/")
        print("Output folder: ", simulation_config["output_folder"])
        if not os.path.exists(simulation_config["output_folder"]):
            os.makedirs(simulation_config["output_folder"])

        info = pre_filtering_simulation(simulation_config, matches, no_content_matches, info)
        info["total_execution_time"] = time() - start
        with open(simulation_config["output_folder"] + "analysis.json", 'a') as f:
            json.dump(info , f, ensure_ascii=False, indent=4)
    elif simulation_type  == "packet_sampling":
        for n in [5, 10, 25, 50]:
            for t in [5, 10, 25]:
                print("PACKET SAMPLING SIMULATION")
                simulation_config["output_folder"] = os.path.join(OUTPUT_FOLDER, f"{dataset_name}/{target_nids}/packet_sampling_{str(n)}_{str(t)}/")
                if not os.path.exists(simulation_config["output_folder"]):
                    os.makedirs(simulation_config["output_folder"])

                info = packet_sampling_simulation(simulation_config, n, t, info)
                info["total_execution_time"] = time() - start
                with open(simulation_config["output_folder"] + "analysis.json", 'a') as f:
                    json.dump(info , f, ensure_ascii=False, indent=4)

    else:
        print("Wrong simulation type")
        exit(-1)


def generate_simulation(simulation_name, dataset_name, target_nids):
    simulation_config = {}
    simulation_config["scenario"] = simulation_name
    base_path = os.path.dirname(os.path.abspath(__file__))
    #simulation_config["pcaps_path"] = "/home/hbeckerbrum/Pre-filtering-Simulator/test_pcaps/"
    simulation_config["pcaps_path"] = f"/home/hbeckerbrum/NFSDatasets/{dataset_name}/"

    simulation_config["nids_name"] = target_nids

    file_ending = "lua" if target_nids == "snort" else "yaml"
    #simulation_config["baseline_alerts_path"] = simulation_config["pcaps_path"]
    simulation_config["baseline_alerts_path"] = os.path.join(base_path, f"../etc/{dataset_name}/alerts/{target_nids}/")
    simulation_config["nids_config_path"] = os.path.join(base_path, f"../etc/{dataset_name}/nids_configuration/{target_nids}/{target_nids}.{file_ending}")
    if target_nids == "snort":
        simulation_config["ruleset_path"] = os.path.join(base_path, "../etc/rules/snort3-registered/")
    else:
        simulation_config["ruleset_path"] = os.path.join(base_path, "../etc/rules/suricata-emerging/emerging-all.rules")

    simulation_config["ipvars_config_path"] = os.path.join(base_path, f"../etc/{dataset_name}/nids_configuration/")
    return simulation_config

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
    parser = argparse.ArgumentParser(description="Run a simulation for pre-filtering or packet sampling.")
    parser.add_argument("simulation_type", choices=["packet_sampling", "pre_filtering"], help="Type of simulation to run.")
    parser.add_argument("dataset_name", choices=["CICIDS2017", "CICIoT2023"], help="Dataset name (CICIDS2017 or CICIoT2023).")
    parser.add_argument("target_nids", choices=["snort", "suricata"], help="Target NIDS (snort or suricata).")
    parser.add_argument("simulation_name", type=str, help="Name of the simulation.", nargs='?', default="")

    args = parser.parse_args()

    simulation_name = args.simulation_name
    simulation_type = args.simulation_type
    dataset_name = args.dataset_name
    target_nids = args.target_nids


    main(simulation_name, simulation_type, dataset_name, target_nids)