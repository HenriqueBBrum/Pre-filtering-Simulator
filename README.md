# Pre-filtering Simulator

This repository contains the code and instructions needed to reproduce the experiments for the paper: []()

This project simulates the pre-filtering of packets for a Network Intrusion Detection System (NIDS) based on its own rules. Two main pre-filtering methods are implemented: flow sampling and rule-based pre-filtering. 

- **Flow sampling** forwards only a fixed number of packets from each flow to the NIDS.
- **Rule-based pre-filtering** uses a simplified version of the NIDS's rules to decide which packets should be forwarded and which should be discarded.

Three rule-based pre-filtering are evaluated in this simulator: two based on existing methods, and one developed and introduced in the aforementioned paper. To obtain the results shown in the paper, follow the instructions starting at [Clone the Repository](#clone-the-repository).

## Repository Structure

```
├── analysis/
├── etc/
├── src/
├── .gitignore
├── README.md
├── requirements.txt
```

- **`analysis/`**: Scripts to process simulator results and plot graphs
- **`etc/`**: NIDS configurations for each dataset, baseline alerts for all packets, and the studied ruleset
- **`src/`**: Source code for the project
    - **`nids_parser/`**: Parsing NIDS rules
    - **`simulator/`**: Pre-filtering simulator
    - **`utils`**: Utility code used by different modules
    - **`main`**: Entry point to start the simulator


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

## Download the Datsets

Before running the simulator, dowload the datasets. Both of them are quite heavy so allocated enough space. 
- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html)

## Install Snort and Suricata

The last step before running the simulator is to install the NIDS:
- [Snort](https://www.snort.org/downloads#snort3-downloads)
- [Suricata](https://suricata.io/download/)

## Running the Simulator

With everything installed, it's time to run the simulator.

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

To obtain the results presented in the paper and generate the final graphs, run the following script:

```

```


## Rulesets

| NIDS | Ruleset | Download date | Rules removed |
|:---:|:---:|:---:|---|
| Snort++ 3.3.7.0 | [Snort 3 Ruleset snapshot-31470](https://www.snort.org/downloads/registered/snortrules-snapshot-31470.tar.gz) | 4 April 2025 |300039:1, 300046:1 |
| Suricata 7.0.8 | [Emerging Threats Suricata 7.0.3](https://rules.emergingthreatspro.com/open/suricata-7.0.3/) | 17 Fev 2025 | - |

