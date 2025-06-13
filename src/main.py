import json
import os
import h5py
import argparse

from time import time

from nids_parser.config_parser import NIDSConfiguration
from nids_parser.rules_to_matches import convert_rules_to_matches
from simulator.rule_based_simulator import rule_based_simulation 
from simulator.packet_sampling_simulator import packet_sampling_simulation

from scapy.all import TCP
from scapy.packet import bind_layers
from scapy.layers.http import HTTP  

from utils.port_services import file_data_ports, port_to_service_map

OUTPUT_FOLDER = "simulation_results/"

def main(args):
    simulation_config = generate_simulation(args.name, args.dataset, args.nids, args.pcaps_path)
    info = {}
    info["type"] = args.type
    start = time()
    if args.type =="rule_based":
        nids_config = NIDSConfiguration(simulation_config["ipvars_config_path"])
        print("*" * 80)
        print("*" * 26 + " NIDS RULES PARSING STAGE " + "*" * 27+ "\n\n")
        matches, no_content_matches, info["number_of_rules"] = convert_rules_to_matches(simulation_config, nids_config)

        # Binds HTTP to the HTTP ports defined in the configuration
        for port_group in nids_config.ports:
            if "HTTP" in port_group:
                for port in nids_config.ports[port_group]:
                    bind_layers(TCP, HTTP, sport=int(port[0]))
                    bind_layers(TCP, HTTP, dport=int(port[0]))
                    port_to_service_map[int(port[0])] = "http"
                    file_data_ports.add(int(port[0]))

        info["number_offloaded_rules"] = len(matches)
        info["time_to_process_rules"] = time()-start
        
        print("PRE-FILTERING SIMULATION")
        print("Scenario: ", simulation_config["scenario"])
        simulation_config["output_folder"] = os.path.join(OUTPUT_FOLDER, f"{args.dataset}/{args.nids}/rule_based_{args.name}/")
        if not os.path.exists(simulation_config["output_folder"]):
            os.makedirs(simulation_config["output_folder"])

        info, comparisons_info = rule_based_simulation(simulation_config, matches, no_content_matches, info)
        info["total_execution_time"] = time() - start
        with open(simulation_config["output_folder"] + "analysis.json", 'a') as f:
            json.dump(info , f, ensure_ascii=False, indent=4)

        # Save the number of comparisons in the h5 format
        with h5py.File(simulation_config["output_folder"] + "num_comparsions.hdf5", "w") as f:
            for trace in comparisons_info:
                group = f.create_group(trace)
                for metric in comparisons_info[trace]:
                    group.create_dataset(metric, data = comparisons_info[trace][metric])
    elif args.type  == "packet_sampling":
        for n in [5, 10, 25, 50]:
            for t in [50]: # 5, 10, 25, 
                print("PACKET SAMPLING SIMULATION")
                simulation_config["output_folder"] = os.path.join(OUTPUT_FOLDER, f"{args.dataset}/{args.nids}/packet_sampling_{str(n)}_{str(t)}/")
                if not os.path.exists(simulation_config["output_folder"]):
                    os.makedirs(simulation_config["output_folder"])

                info = packet_sampling_simulation(simulation_config, n, t, info)
                info["total_execution_time"] = time() - start
                with open(simulation_config["output_folder"] + "analysis.json", 'a') as f:
                    json.dump(info , f, ensure_ascii=False, indent=4)

    else:
        print("Wrong simulation type")
        exit(-1)


def generate_simulation(name, dataset, nids, pcaps_path):
    simulation_config = {}
    simulation_config["scenario"] = name
    base_path = os.path.dirname(os.path.abspath(__file__))
    simulation_config["pcaps_path"] = f"{pcaps_path}/{dataset}/"
    simulation_config["nids_name"] = nids

    simulation_config["baseline_alerts_path"] = os.path.join(base_path, f"../etc/{dataset}/alerts/{nids}/")

    file_ending = "lua" if nids == "snort" else "yaml"
    simulation_config["nids_config_path"] = os.path.join(base_path, f"../etc/{dataset}/nids_configuration/{nids}/{nids}.{file_ending}")
    if nids == "snort":
        simulation_config["ruleset_path"] = os.path.join(base_path, "../etc/rules/snort3-registered/")
    else:
        simulation_config["ruleset_path"] = os.path.join(base_path, "../etc/rules/suricata-emerging/emerging-all.rules")

    simulation_config["ipvars_config_path"] = os.path.join(base_path, f"../etc/{dataset}/nids_configuration/")
    return simulation_config


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Run a simulation for packet sampling or rule-based pre-filtering.")

    parser.add_argument("--name", type=str, help="Name of the simulation.", nargs='?', default="")
    parser.add_argument("-t", "--type", choices=["packet_sampling", "rule_based"], help="Type of simulation to run.", required=True)
    parser.add_argument("-d", "--dataset", choices=["CICIDS2017", "CICIoT2023"], help="Dataset name (CICIDS2017 or CICIoT2023).", required=True)
    parser.add_argument("-n" ,"--nids", choices=["snort", "suricata"], help="Target NIDS (snort or suricata).", required=True)
    parser.add_argument("-p", "--pcaps_path", type=str, help="Folder path for the pcaps to input for the simulator", required=True)

    main(parser.parse_args())