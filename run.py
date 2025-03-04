import sys

def main():
    if len(sys.argv) != 5:
        print("Usage: python script.py <simulation_type> <nids_name> <baseline_alerts_path> <ruleset_path>")
        sys.exit(1)
    
    simulation_type = sys.argv[1]
    nids_name = sys.argv[2]
    baseline_alerts_path = sys.argv[3]
    ruleset_path = sys.argv[4]
    
    print("Simulation Type:", simulation_type)
    print("NIDS Name:", nids_name)
    print("Baseline Alerts Path:", baseline_alerts_path)
    print("Ruleset Path:", ruleset_path)
    
    # Placeholder for additional processing logic
    process_simulation(simulation_type, nids_name, baseline_alerts_path, ruleset_path)

def process_simulation(simulation_type, nids_name, baseline_alerts_path, ruleset_path):
    print("Processing simulation...")
    # Implement your logic here
    pass

if __name__ == "__main__":
    main()
