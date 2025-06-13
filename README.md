# Pre-filtering for NIDS Simulator

This project is a simulator that pre-filters packets to a NIDS based on the NIDS' own rules. There are two main pre-filtering methods simulated in this code: flow sampling and rule-based pre-filtering. 

- Flow sampling works by fowarding to the NIDS only a fixed amount of packets from each flow to the NIDS
- Rule-based pre-filtering uses a simplfieid vrsion of the NIDS own rules, and uses them to determine what packets should be fowarded and what packets should be discaredd.

This repository contains the code and instructions needed to reproduce the experiments for the paper:


## Instalation Guide

```
git clone 
```

The simulator is a Python program, so install Python3.

Then, create a venv and install de required packegs:
```bash
pip install -r requirements.txt
```

Install Rscript for the analysis of the simulator results

```
sudo apt-get install littler
```

That's it!


## Running

By default, the output_folder of the is  


Open a tmux window, and run the following command with the desired arguments:


## Repository Structure

```
├── analysis/
├── etc/
├── src/
├── .gitignore
├── README.md
```

- **`analysis/`**: The scripts required to process the simulator's results and plot graphs;

- **`etc/`**: Contains the NIDS's configurations for each dataset, the baseline alerts when the NIDS process all packets, and the ruleset studied;

- **`src/`**: Folder containing the source code for this project;
	- **`nids_parser/`**: Parser of NIDS rules;
	- **`simulator/`**: The simulator's code;
	- **`utils`**: Files containing code used by different files or with specific purpose;
	- **`main`**: Main file that is called to start the simulator;