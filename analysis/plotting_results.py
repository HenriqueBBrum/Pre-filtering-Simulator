import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import os
import argparse

from matplotlib.ticker import MaxNLocator

def experiments_new_alerts(df, dataset_name, nids_name, nids_dataset_output_dir):
    for metric in ["alerts_false_positive_percent", "alerts_false_positive_absolute"]:
        metric_df = df[["pcap", "experiment", metric]]
        plot_df = metric_df.pivot_table(index='pcap', columns='experiment', values=metric, sort=False)
        # Group the PCAPs into chunks of 5 and plot each group
        for i in range(0, len(plot_df), 5):
            group_df = plot_df.iloc[i:i+5]
            if dataset_name == "CICIDS2017":
                group_df.index = pd.Categorical(plot_df.index, categories=["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"], ordered=True)
                group_df = group_df.sort_index()

            group_plot = group_df.plot(kind='line', style=['o--', 'v--', 's-', 'x-', 'p-'], xlabel='')
            ax = plt.gca()
            if "percent" in metric:
                plt.gca().yaxis.set_major_formatter(mtick.PercentFormatter(xmax=100))
                ax.set_ylim([-5, 105])
            else:
                ax.yaxis.set_major_locator(MaxNLocator(integer=True))
                if group_df.to_numpy().sum() == 0:
                    ax.set_ylim([-0.05, 1])

            handles, labels = plt.gca().get_legend_handles_labels()
            sorted_experiments = ["PS N=5 T=25s", "PS N=50 T=5s", "Fast Pattern","Extended"]
            sorted_handles_labels = sorted(zip(handles, labels), key=lambda x: sorted_experiments.index(x[1]))
            handles, labels = zip(*sorted_handles_labels)

            if dataset_name == "CICIoT2023":
                plt.xticks(rotation=8, fontsize=9)

            plt.title(f"Signatures only in the experiments ({nids_name.title()}, {dataset_name})")
            metric_sign = "#"
            if "percent" in metric:
                metric_sign = "%"
            plt.ylabel(f"{metric_sign} new alerts")
            plt.legend(title=None, handles=handles, labels=labels)
            plt.tight_layout()

            # Save the graph for the current group
            if dataset_name == "CICIDS2017": 
                plt.savefig(f"{nids_dataset_output_dir}/experiment_only_alerts_{metric_sign}.png", dpi=300)
            else:
                plt.savefig(f"{nids_dataset_output_dir}/experiment_only_alerts__{metric_sign}_{int(i/5)}.png", dpi=300)
            plt.close()


def filteredXalerts(df, dataset_name, nids_name, nids_dataset_output_dir, ):
    # Get unique values for "pkts_processed" and "total_baseline_alerts" for each "pcap"
    for pcap, group in df.groupby("pcap"):
        fig, ax = plt.subplots()
        pkts_processed_unique = df.groupby("pcap")["pkts_processed"].unique()
        total_baseline_alerts_unique = df.groupby("pcap")["total_baseline_alerts"].unique()

        bar_width = 0.2
        x = range(len(group["experiment"]))

        # Sort the group by the specified experiment order
        experiment_order = ["PS N=5 T=25s", "PS N=50 T=5s", "Fast Pattern", "Extended"]
        group = group.set_index("experiment").reindex(experiment_order).reset_index()

        # Bar graph for pkts_filtered_absolute
        ax.bar([i - bar_width / 2 for i in x], group["pkts_filtered_absolute"], width=bar_width, color='coral', alpha=0.5, hatch='//', label="# suspicious packets")
        ax.set_ylabel("# packets filtered", color='coral')
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
        ax2.bar([i + bar_width / 2 for i in x], group[f"alerts_true_positive_absolute"], width=bar_width, color='royalblue', alpha=0.6, hatch='\\', label="# alerts correctly identified")
        ax2.set_ylabel(f"# alerts correctly identified", color='royalblue')
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

        plt.tight_layout()
        plt.title(f"{pcap} ({nids_name.title()}, {dataset_name})")
        plt.savefig(f"{nids_dataset_output_dir}/{pcap}.png", dpi=300)
        plt.close()


def rules_comparison_table(df, nids_dataset_output_dir):
    # Calculate the average and standard deviation for each metric grouped by experiment
    metrics = ["avg_num_rules_compared_to", "avg_num_contents_compared_to", "avg_num_pcre_compared_to"]
    table_data = []

    for experiment, group in df.groupby("experiment"):
        row = [experiment]
        for metric in metrics:
            avg = group[metric].mean()
            std = group[metric].std()
            row.extend([f"{avg:.2f}", f"{std:.2f}"])
        table_data.append(row)

    table_df = pd.DataFrame(table_data, columns=["experiment"] + [f"{metric} ({name})" for metric in metrics for name in ("avg", "std")])
    table_df.to_csv(f"{nids_dataset_output_dir}/rules_comparison.csv", index=False)


if __name__ == "__main__":
    data_for_global_plot = {}
    output_dir = "graphs"
    os.makedirs(output_dir, exist_ok=True)
    for dataset_name in ["CICIDS2017", "CICIoT2023"]:
        for target_nids in ["snort", "suricata"]:
            
            nids_dataset_output_dir = f"{output_dir}/{dataset_name}_{target_nids}"
            os.makedirs(nids_dataset_output_dir, exist_ok=True)

            print(f"Generating graphs for {dataset_name} with {target_nids}...")
            data = pd.read_csv(f"csv/{dataset_name}_{target_nids}.csv")
            df = data[data['experiment'].isin(["packet_sampling_5_25", "packet_sampling_50_5", "rule_based_fast_pattern","rule_based_extended"])]
            # Update the experiment column with new names
            experiment_mapping = {
                "packet_sampling_5_25": "PS N=5 T=25s",
                "packet_sampling_50_5": "PS N=50 T=5s",
                "rule_based_fast_pattern": "Fast Pattern",
                "rule_based_extended": "Extended"
            }
            df.loc[:, 'experiment'] = df['experiment'].map(experiment_mapping)

            for experiment, group in df.groupby("experiment"):
                total_pkts_processed = group["pkts_processed"].sum().item()
                total_baseline_alerts = group["total_baseline_alerts"].sum().item()
                
                total_pkts_filtered = group["pkts_filtered_absolute"].sum().item()
                pkts_filtered_percentage = (total_pkts_filtered/total_pkts_processed) * 100

                total_experiment_alerts = group["alerts_true_positive_absolute"].sum().item()
                alerts_percentage = (total_experiment_alerts/total_baseline_alerts) * 100

                data_for_global_plot[dataset_name+"-"+target_nids+"-"+experiment] = {"pkts_filtered": pkts_filtered_percentage, "experiment_alerts": alerts_percentage}
        
            experiments_new_alerts(df, dataset_name, target_nids, nids_dataset_output_dir)
            filteredXalerts(df, dataset_name, target_nids, nids_dataset_output_dir)

            df = data[data['experiment'].isin(["rule_based_fast_pattern", "rule_based_extended"])]
            experiment_mapping = {
                "rule_based_fast_pattern": "Fast Pattern",
                "rule_based_extended": "Extended"
            }
            df.loc[:, 'experiment'] = df['experiment'].map(experiment_mapping)

            rules_comparison_table(df, nids_dataset_output_dir)

    # Create a point graph for data_for_global_plot
    fig, ax = plt.subplots(figsize=(10, 6))

    # Define color and hatch mappings
    dataset_nids_colors = {
        "CICIDS2017-Snort": "darkorange",
        "CICIDS2017-Suricata": "peachpuff",
        "CICIoT2023-Snort": "darkmagenta",
        "CICIoT2023-Suricata": "plum"
    }
    experiment_markers = {"PS N=5 T=25s": "P", "PS N=50 T=5s": "X", "Fast Pattern": "s", "Extended": "^"}
    ax.axvspan(60, 100, ymin=0.587, ymax=0.98, facecolor='lightgreen', alpha=0.2, linestyle=':')

    for key, values in data_for_global_plot.items():
        dataset, nids, experiment = key.split("-")
        final_key = f"{dataset}-{nids.capitalize()} {experiment}"
        color = dataset_nids_colors.get(f"{dataset}-{nids.capitalize()}", "black")
        marker = experiment_markers.get(experiment, "")
        
        ax.scatter(
            values["experiment_alerts"], 
            values["pkts_filtered"], 
            label=final_key, 
            color=color, 
            edgecolor="black", 
            linewidth=0.8, 
            s=100, 
            marker=marker
        )

    # Add labels, legend, and title
    ax.set_xlabel("% alerts correctly identified")
    ax.set_ylabel("% packets filtered")
    ax.set_xlim([0, 102])
    ax.xaxis.set_major_formatter(mtick.PercentFormatter())
    ax.set_ylim([0, 102])
    ax.yaxis.set_major_formatter(mtick.PercentFormatter())

    ax.set_title("Packets Filtered vs Alerts Correctly Identified")    
    experiment_legend = [
        plt.Line2D([0], [0], marker=marker, color="white", markeredgecolor='black', linestyle='None', markersize=10, label=key)
        for key, marker in experiment_markers.items()
    ]
    legend1 = ax.legend(handles=experiment_legend, loc="upper left", bbox_to_anchor=(1, 0.8), title="Experiments", fontsize=8)
    # Add the first legend to the plot
    ax.add_artist(legend1)

    dataset_nids_legend = [
        plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=10, label=key)
        for key, color in dataset_nids_colors.items()
    ]
    ax.legend(handles=dataset_nids_legend, loc="upper left", bbox_to_anchor=(1, 1), title="Dataset-NIDS", fontsize=8)

    # Add grid lines
    ax.grid(True, linestyle="--", alpha=0.6)

    # Adjust layout and save the plot
    plt.tight_layout()
    plt.savefig(f"{output_dir}/packets_alerts_global.png", dpi=300)
    plt.show()
