# Pre-filtering Simulator

This repository contains the code and instructions needed to reproduce the experiments for the paper: [Rethinking NIDS Rule-Based Pre-Filtering]()

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

The simulator is written in Python. Python 3.12.3 was used for development.

Create a venv  and install the required Python libraries:

```bash
pip install -r requirements.txt
```

Install `littler` (Rscript) for analyzing the simulator results:

```bash
sudo apt-get install littler
```

That's it!

## Download the Datasets

Before running the simulator, dowload the datasets and its pcaps. Both of them are quite heavy so allocated enough space. 

- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html)

For ease of use, create a folder for each dataset, named `CICIDS2017` or `CICIoT2023`, and place the corresponding PCAPs inside

When using the `CICIoT2023` dataset, exclude all PCAPs whose filenames start with `DoS`, `DDoS`, `Mirai`, or `MITM`. The only exceptions are `DDoS-SlowLoris.pcap`, `MITM-ArpSpoofing.pcap`, and `DoS-HTTP_Flood.pcap`, which should be included. All other PCAPs in the dataset were used.

## Install Snort

The last step before running the simulator is to install [Snort 3](https://www.snort.org/downloads#snort3-downloads). Please refer to their official installation guide, as the process can be somewhat complex.

## Running the Simulator

With everything installed, it's time to run the simulator.

By default, the simulator outputs results to the `simulation_results/` folder at the same level as this README. You can change this folder, but note that `analysis/get_pcap_infor.r` expects results in this location.

Open a tmux window and run the following command with your desired arguments:

```bash
python3 src/main.py --name <NAME> -t <TYPE> -d <DATASET> -n <NIDS> -p <PCAPS_PATH>
```

- `<NAME>`: (Optional) Name identifying the experiment you are running  
- `<TYPE>`: Type of simulation to run (`flow_sampling` or `rule_based`)
- `<DATASET>`: Dataset name (`CICIDS2017` or `CICIoT2023`) 
- `<NIDS>`: NIDS name (`snort`)
- `<PCAPS_PATH>`: Path to the dataset's pcap folders. The dataset name is used with this option to find the path to the pcaps 

To obtain the results presented in the paper and generate the final graphs, run the following scripts.

First, run the `get_pcap_info.r` script that generates intermediate csv files: 

```
Rscript get_pcap_info.r
```

The simulation results should be on the same level as the `analysis/` folder.

Then, with the csv generated, run the plotting script:

```
python3 plotting_results.py 
```


## Rulesets

| NIDS | Ruleset | Download date | Rules removed |
|:---:|:---:|:---:|---|
| Snort++ 3.7.4 | [Snort 3 Ruleset snapshot-31470](https://www.snort.org/downloads/registered/snortrules-snapshot-31470.tar.gz) | 4 April 2025 |300039:1, 300046:1 |


## Raw data used in the paper

This [link](https://drive.google.com/drive/folders/1XO0U8dH7sWBnpu1fjq4jxlD0sL-sIANB?usp=sharing) contains the raw simulation data that was used to generate the plots. 

To generate the plots, download the folders in this link and add to the `simulation_results/` in this repo. Then, run the previous steps with the R language and Python.
