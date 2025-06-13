# Pre-filteringSimulator

This project simulates pre-filtering of packets for a Network Intrusion Detection System (NIDS) based on its own rules. Two main pre-filtering methods are implemented: flow sampling and rule-based pre-filtering.

- **Flow sampling** forwards only a fixed number of packets from each flow to the NIDS.
- **Rule-based pre-filtering** uses a simplified version of the NIDS's rules to decide which packets should be forwarded and which should be discarded.

This repository contains the code and instructions needed to reproduce the experiments for the paper: ()[]

## Clone the Repository

```bash
git clone https://github.com/HenriqueBBrum/Pre-filtering-Simulator.git
```

## Install Dependencies

The simulator is written in Python. Python 3.10.12 was used for development.

Install the required Python libraries:

```bash
pip install -r requirements.txt
```

Install `littler` (Rscript) for analyzing the simulator results:

```bash
sudo apt-get install littler
```

That's it!

## Running the Simulator

By default, the simulator outputs results to the `simulation_results/` folder at the same level as this README. You can change this folder, but note that `analysis/get_pcap_infor.r` expects results in this location.

Open a tmux window and run the following command with your desired arguments:

```bash
python3 src/main.py --name <NAME> -t <TYPE> -d <DATASET> -n <NIDS> -p <PCAPS_PATH>
```

- `<NAME>`: (Optional) Name identifying the experiment you are running  
- `<TYPE>`: Type of simulation to run (`packet_sampling` or `rule_based`)
- `<DATASET>`: Dataset name (`CICIDS2017` or `CICIoT2023`)
- `<NIDS>`: NIDS name (`snort` or `suricata`)
- `<PCAPS_PATH>`: Path to the dataset's pcap folders

To reproduce all results presented in the paper, run the following script:

```

```

## Repository Structure

```
├── analysis/
├── etc/
├── src/
├── .gitignore
├── README.md
```

- **`analysis/`**: Scripts to process simulator results and plot graphs
- **`etc/`**: NIDS configurations for each dataset, baseline alerts for all packets, and the studied ruleset
- **`src/`**: Source code for the project
    - **`nids_parser/`**: NIDS rule parser
    - **`simulator/`**: Simulator code
    - **`utils`**: Utility code used by different modules
    - **`main`**: Entry point to start the simulator
