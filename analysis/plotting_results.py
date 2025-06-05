import os
import h5py
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
from matplotlib.ticker import MaxNLocator
import numpy as np
import argparse

experiment_mapping = {
                "packet_sampling_5_25": "FS N=5 T=25s",
                "packet_sampling_50_5": "FS N=50 T=5s",
                "rule_based_header_only": "Header Only",
                "rule_based_fast_pattern": "Fast Pattern",
                "rule_based_extended": "Extended"
            }

experiments_name = ["FS N=5 T=25s", "FS N=50 T=5s", "Header Only", "Fast Pattern","Extended"]


def fowardedXalerts(df, dataset_name, nids_name, graph_output_dir):
    # Get unique values for "pkts_processed" and "total_baseline_alerts" for each "pcap"
    for pcap, group in df.groupby("pcap"):
        fig, ax = plt.subplots()
        pkts_processed_unique = df.groupby("pcap")["pkts_processed"].unique()
        total_baseline_alerts_unique = df.groupby("pcap")["total_baseline_alerts"].unique()

        bar_width = 0.2
        x = range(len(group["experiment"]))

        # Sort the group by the specified experiment order
        group = group.set_index("experiment").reindex(experiments_name).reset_index()

        # Bar graph for pkts_fowarded_absolute
        ax.bar([i - bar_width / 2 for i in x], group["pkts_fowarded_absolute"], width=bar_width, color='coral', alpha=0.8, hatch='//', label="# suspicious packets")
        ax.set_ylabel("# of packets fowarded", color='coral')
        ax.tick_params(axis='y', labelcolor='coral')
        ax.set_xticks(x)
        ax.set_xticklabels(group["experiment"], size=8)
        max_value = pkts_processed_unique[pcap][0] if len(pkts_processed_unique[pcap]) > 0 else 0

        # Add a horizontal line delimiting the max value for the primary Y-axis
        if max_value > 0:
            ax.axhline(y=max_value, color='coral', linestyle='--', linewidth=1, label="Max suspicious packets")
            ax.text(len(x) - 1, max_value, "# of baseline packets", color='coral', fontsize=8, ha='right', va='bottom')
            ax.set_yticks(range(0, int(max_value) + 1, max(1, int(max_value // 5))))
            ax.set_ylim([0, max_value*1.05])

        # Secondary y-axis for alerts_true_positive_absolute
        ax2 = ax.twinx()
        ax2.bar([i + bar_width / 2 for i in x], group[f"alerts_true_positive_absolute"], width=bar_width, color='royalblue', alpha=0.8, hatch='\\', label="# alerts correctly identified")
        ax2.set_ylabel(f"# of alerts correctly identified", color='royalblue')
        ax2.tick_params(axis='y', labelcolor='royalblue')
        ax2.yaxis.set_major_locator(MaxNLocator(integer=True))
        max_value = total_baseline_alerts_unique[pcap][0]
        ax2.set_ylim([0, 1])
        
        # Add a horizontal line delimiting the max value for the secondary Y-axis
        if max_value > 0:
            ax2.axhline(y=max_value, color='royalblue', linestyle='--', linewidth=1)
            ax2.text(len(x) - 1, max_value, f"# of baseline alerts", color='royalblue', fontsize=8, ha='right', va='bottom')
            ax2.set_yticks(range(0, int(max_value) + 1, max(1, int(max_value // 5))))
            ax2.set_ylim([0, max_value*1.1])

        plt.title(f"{pcap} ({dataset_name}, {nids_name.title()})")
        plt.tight_layout()
        plt.savefig(f"{graph_output_dir}/{pcap}.png", dpi=300)
        plt.close()


def overview_of_forwardedXalerts(data_for_global_plot, graph_output_dir):
    fig, ax = plt.subplots(figsize=(10, 6))
    nids_colors = {
        "Snort": "#9c1412",
        "Suricata": "#f5aa32"
    }
    experiment_markers = {"FS N=5 T=25s": "P", "FS N=50 T=5s": "X", "Header Only": "^", "Fast Pattern": "s", "Extended": "p"}

    for key, values in data_for_global_plot.items():
        experiment, nids = key.split("-")
        label = f"{nids.capitalize()} {experiment}"
        color = nids_colors.get(f"{nids.capitalize()}", "black")
        marker = experiment_markers.get(experiment, "")
        
        ax.scatter(
            values["experiment_alerts"], 
            values["pkts_fowarded"], 
            label=label, 
            color=color, 
            edgecolor="black", 
            linewidth=0.8, 
            s=100, 
            marker=marker
        )

    # Add labels, legend, and title
    ax.set_xlim([0, 102])
    ax.xaxis.set_major_formatter(mtick.PercentFormatter())
    ax.set_xlabel("% of alerts correctly identified " + r"($\bf{higher}$ is better)")
    ax.set_ylim([0, 102])
    ax.yaxis.set_major_formatter(mtick.PercentFormatter())
    ax.set_ylabel("% of packets fowarded " +  r"($\bf{lower}$ is better)")

    ax.set_title("Packets Fowarded vs Alerts Correctly Identified")    
  
    nids_legend = [
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=10, label=key)
        for key, color in nids_colors.items()
    ]
    legend1 =  ax.legend(handles=nids_legend, loc="upper left", bbox_to_anchor=(1.025, 1), title="NIDS", fontsize=10)
    ax.add_artist(legend1)
    experiment_legend = [
        plt.Line2D([0], [0], marker=marker, color="white", markeredgecolor='black', linestyle='None', markersize=10, label=key)
        for key, marker in experiment_markers.items()
    ]
    ax.legend(handles=experiment_legend, loc="upper left", bbox_to_anchor=(1, 0.85), title="Method", fontsize=10)
    ax.grid(True, linestyle="--", alpha=0.6)

    plt.tight_layout()
    plt.savefig(f"{graph_output_dir}/overview_forwardedXalerts.png", dpi=300)
    plt.show()


def performance(performance_data, graph_output_dir):
    metric_keys = ["header", "content", "pcre"]
    metric_labels = ["Header", "Content", "PCRE"]
    metric_colors = ["coral", "royalblue", "seagreen"]
    mean_color = "red"
    for nids, data in performance_data.items():
        fig, axes = plt.subplots(1, 3, figsize=(18, 6), sharey=False)
        for idx, (metric, label, color) in enumerate(zip(metric_keys, metric_labels, metric_colors)):
            ax = axes[idx]
            boxplot_data = [data[exp][metric] for exp in data]
            box = ax.boxplot(boxplot_data, patch_artist=True,
                        boxprops=dict(facecolor=color, color=color),
                        medianprops=dict(color='black'),
                        whiskerprops=dict(color=color),
                        capprops=dict(color=color),
                        showmeans=True,
                        meanline=True,
                        flierprops=dict(markerfacecolor=color, marker='o', markersize=5, alpha=0.5))
            
            for mean in box["means"]:
                mean.set_color(mean_color)
            
            ax.set_title(label)
            ax.set_xticks(range(1, len(data) + 1))
            ax.set_xticklabels(data.keys(), fontsize=12)
            if idx == 0:
                ax.set_ylabel(f"# of comparisons", fontsize=12)

            medians = [np.median(data[exp][metric]) for exp in data]
            for i, median in enumerate(medians, 1):
                ax.annotate(f"{int(median)}", xy=(i, median), xytext=(25, 0), textcoords="offset points",
                    va='center', ha='left', fontsize=8, color="black")
                
            avgs = [np.average(data[exp][metric]) for exp in data]
            for i, avg in enumerate(avgs, 1):
                ax.annotate(f"{avg:.1f}", xy=(i, avg), xytext=(-25, 0), textcoords="offset points",
                    va='center', ha='right', fontsize=8, color=mean_color)
                
        # Legend for mean and median lines
        mean_line = plt.Line2D([0], [0], color=mean_color, linestyle='--', linewidth=2, label='Mean')
        median_line = plt.Line2D([0], [0], color='black', linestyle='-', linewidth=2, label='Median')
        axes[-1].legend(handles=[mean_line, median_line], loc='center left', bbox_to_anchor=(1.02, 1), fontsize=12)

        plt.tight_layout()
        plt.savefig(f"{graph_output_dir}/{nids}_performance.png", dpi=300)
        plt.close()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plotting results for pre-filtering simulator.")
    parser.add_argument(
        "--simulation_results_dir",
        type=str,
        default="../simulation_results/",
        help="Directory containing simulation results files."
    )
    args = parser.parse_args()

    data_for_global_plot = {}
    performance_data = {}
    output_dir = "graphs"
    os.makedirs(output_dir, exist_ok=True)
    for dataset_name in ["CICIDS2017", "CICIoT2023"]:
        for target_nids in ["snort", "suricata"]:
            graph_output_dir = f"{output_dir}/{dataset_name}_{target_nids}"
            os.makedirs(graph_output_dir, exist_ok=True)

            print(f"Generating graphs for {dataset_name} with {target_nids}...")
            data = pd.read_csv(f"csv/{dataset_name}_{target_nids}.csv")
            df = data[data['experiment'].isin(experiment_mapping)]            
            df.loc[:, 'experiment'] = df['experiment'].map(experiment_mapping)

            for exp, group in df.groupby("experiment"):
                total_pkts_processed = group["pkts_processed"].sum().item()
                total_pkts_fowarded = group["pkts_fowarded_absolute"].sum().item()

                total_baseline_alerts = group["total_baseline_alerts"].sum().item()
                total_experiment_alerts = group["alerts_true_positive_absolute"].sum().item()

                key = exp+"-"+target_nids
                if key in data_for_global_plot:
                    total_pkts_processed+=data_for_global_plot[key]["total_pkts_processed"]
                    total_pkts_fowarded+=data_for_global_plot[key]["total_pkts_fowarded"]
                    total_baseline_alerts+=data_for_global_plot[key]["total_baseline_alerts"]
                    total_experiment_alerts+=data_for_global_plot[key]["total_experiment_alerts"]
                    pkts_fowarded_percentage = (total_pkts_fowarded/total_pkts_processed) * 100
                    alerts_percentage = (total_experiment_alerts/total_baseline_alerts) * 100
                    data_for_global_plot[key] = {"pkts_fowarded": pkts_fowarded_percentage, "experiment_alerts": alerts_percentage}
                else:
                    data_for_global_plot[key] = {"total_pkts_processed": total_pkts_processed, "total_pkts_fowarded": total_pkts_fowarded, 
                                                 "total_baseline_alerts": total_baseline_alerts, "total_experiment_alerts": total_experiment_alerts}

                if "FS" not in exp:
                    experiment_filename = list(experiment_mapping.keys())[list(experiment_mapping.values()).index(exp)]
                    filepath = f"{args.simulation_results_dir}{dataset_name}/{target_nids}/{experiment_filename}/num_comparsions.hdf5" 
                    if target_nids not in performance_data:
                        performance_data[target_nids] = {}

                    if exp not in performance_data[target_nids]:
                        performance_data[target_nids][exp] = {"header": np.array([]), "content": np.array([0]), "pcre": np.array([0])}

                    with h5py.File(filepath, 'r') as f:
                        for trace in f.keys():
                            for metric in f[trace].keys():
                                if "header" in metric:
                                    performance_data[target_nids][exp]["header"] = np.concatenate((performance_data[target_nids][exp]["header"], f[trace][metric][:]))
                                elif "content" in metric:
                                    performance_data[target_nids][exp]["content"] = np.concatenate((performance_data[target_nids][exp]["content"], f[trace][metric][:]))
                                elif "pcre" in metric:
                                    performance_data[target_nids][exp]["pcre"] = np.concatenate((performance_data[target_nids][exp]["pcre"], f[trace][metric][:]))
                    
            fowardedXalerts(df, dataset_name, target_nids, graph_output_dir)

    performance(performance_data, output_dir)

    overview_of_forwardedXalerts(data_for_global_plot, output_dir)

   