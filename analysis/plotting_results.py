import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import os
import argparse

def line_graphs(dataset_name, nids_name, csv_filepath):
    # Load data from the specified CSV file
    data = pd.read_csv(csv_filepath)
    df = data[data['experiment'].isin(["packet_sampling_10_25", "packet_sampling_50_5", "pre_filtering_wang_chang", "pre_filtering_old", "pre_filtering_full"])]
    # Update the experiment column with new names
    experiment_mapping = {
        "packet_sampling_10_25": "PS N=10 T=25s",
        "packet_sampling_50_5": "PS N=50 T=5s",
        "pre_filtering_wang_chang": "Fast pattern",
        "pre_filtering_old": "Old work",
        "pre_filtering_full": "Our work"
    }
    df['experiment'] = df['experiment'].map(experiment_mapping)

    # Get unique values for "pkts_processed" and "total_baseline_signatures" for each "pcap"
    pkts_processed_unique = df.groupby("pcap")["pkts_processed"].unique()
    total_baseline_signatures_unique = df.groupby("pcap")["total_baseline_signatures"].unique()

    metrics_name = [("suspicious_pkts_percent", "Packets forwarded to NIDS", "% of packets forwarded", pkts_processed_unique, "# packets"), 
                    ("signatures_true_positive_percent", "Signatures correctly identified", "% of signatures correctly identified", total_baseline_signatures_unique, "# baseline signatures"),]
                     #("signatures_false_positive_percent", "Signatures only in the experiments", "% of new signatures", total_baseline_signatures_unique, "# experiments signatures"),]
                    #("pkt_processing_time", "Simulator avg. pkt. processing time", "seconds"), ("snort_processing_time", "Snort processing time", "seconds")]


    for metric, title, ylabel, top_x_df, top_x_legend in metrics_name:
        metric_df = df[["pcap", "experiment", metric]]
        plot_df = metric_df.pivot_table(index='pcap', columns='experiment', values=metric, sort=False)
        # Group the PCAPs into chunks of 5 and plot each group
        for i in range(0, len(plot_df), 5):
            group_df = plot_df.iloc[i:i+5]
            if dataset_name == "CICIDS2017":
                group_df.index = pd.Categorical(plot_df.index, categories=["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"], ordered=True)
                group_df = group_df.sort_index()

            group_plot = group_df.plot(kind='line', style=['o--', 'v--', 's-', 'x-', 'p-'], xlabel='')
            if "percent" in metric:
                plt.gca().yaxis.set_major_formatter(mtick.PercentFormatter(xmax=100))
                ax = plt.gca()
                ax.set_ylim([-5, 105])

                secax = ax.secondary_xaxis('top')
                secax.set_ticks(range(len(group_df.index)))
                secax.set_xticklabels(top_x_df[group_df.index].apply(lambda x: x[0] if len(x) > 0 else ""), size=7)
                secax.set_xlabel(top_x_legend, size=7)

            handles, labels = plt.gca().get_legend_handles_labels()
            sorted_experiments = ["PS N=10 T=25s", "PS N=50 T=5s", "Fast pattern", "Old work", "Our work"]
            sorted_handles_labels = sorted(zip(handles, labels), key=lambda x: sorted_experiments.index(x[1]))
            handles, labels = zip(*sorted_handles_labels)

            if dataset_name == "CICIoT2023":
                plt.xticks(rotation=15, fontsize=8)

            plt.title(f"{title} ({nids_name.title()}, {dataset_name})")
            plt.ylabel(ylabel)
            plt.legend(title=None, handles=handles, labels=labels)
            plt.tight_layout()

            # Save the graph for the current group
            output_dir = "graphs"
            os.makedirs(output_dir, exist_ok=True)
            nids_dataset_output_dir = f"{output_dir}/{dataset_name}_{nids_name}"
            os.makedirs(nids_dataset_output_dir, exist_ok=True)
            if dataset_name == "CICIDS2017": 
                plt.savefig(f"{nids_dataset_output_dir}/{metric}.png", dpi=300)
            else:
                plt.savefig(f"{nids_dataset_output_dir}/{metric}_{int(i/5)}.png", dpi=300)
            plt.close()


def bar_graphs(dataset_name, nids_name, csv_filepath):
    # Load data from the specified CSV file
    data = pd.read_csv(csv_filepath)
    df = data[data['experiment'].isin(["packet_sampling_10_25", "packet_sampling_50_5", "pre_filtering_wang_chang", "pre_filtering_old", "pre_filtering_full"])]
    # Update the experiment column with new names
    experiment_mapping = {
        "packet_sampling_10_25": "PS N=10 T=25s",
        "packet_sampling_50_5": "PS N=50 T=5s",
        "pre_filtering_wang_chang": "Fast pattern",
        "pre_filtering_old": "Old work",
        "pre_filtering_full": "Our work"
    }
    df['experiment'] = df['experiment'].map(experiment_mapping)

    # Get unique values for "pkts_processed" and "total_baseline_signatures" for each "pcap"
    pkts_processed_unique = df.groupby("pcap")["pkts_processed"].unique()
    total_baseline_signatures_unique = df.groupby("pcap")["total_baseline_signatures"].unique()

    # Create bar graphs for each entry in "pcap"
    for pcap, group in df.groupby("pcap"):
        fig, ax1 = plt.subplots()

        # Bar graph for suspicious_pkts_absolute
        bar_width = 0.2
        x = range(len(group["experiment"]))

        # Sort the group by the specified experiment order
        experiment_order = ["PS N=10 T=25s", "PS N=50 T=5s", "Fast pattern", "Old work", "Our work"]
        group = group.set_index("experiment").reindex(experiment_order).reset_index()

        # Bar graph for suspicious_pkts_absolute
        ax1.bar([i - bar_width / 2 for i in x], group["suspicious_pkts_absolute"], width=bar_width, color='coral', alpha=0.5, hatch='//', label="# suspicious packets")
        ax1.set_xlabel("Experiment name")
        ax1.set_ylabel("# packets fowarded", color='coral')
        ax1.tick_params(axis='y', labelcolor='coral')
        ax1.set_xticks(x)
        ax1.set_xticklabels(group["experiment"], size=8)
        # ax1.set_ylim([0, pkts_processed_unique[pcap][0] * 1.1 if len(pkts_processed_unique[pcap]) > 0 else 0])
        max_value = pkts_processed_unique[pcap][0] if len(pkts_processed_unique[pcap]) > 0 else 0
        ax1.set_ylim([0, max_value * 1.05])
        #ax1.set_yticks(range(0, int(max_value * 1.05) + 1, max(1, int(max_value / 5))))


        # Add a horizontal line delimiting the max value for the primary Y-axis
        if len(pkts_processed_unique[pcap]) > 0:
            ax1.axhline(y=pkts_processed_unique[pcap][0], color='coral', linestyle='--', linewidth=1, label="Max suspicious packets")
            ax1.text(len(x) - 1, pkts_processed_unique[pcap][0], "baseline n. packets", color='coral', fontsize=8, ha='right', va='bottom')

        # Secondary y-axis for signatures_true_positive_absolute
        ax2 = ax1.twinx()
        ax2.bar([i + bar_width / 2 for i in x], group["signatures_true_positive_absolute"], width=bar_width, color='royalblue', alpha=0.6, hatch='\\', label="# signatures correctly identified")
        ax2.set_ylabel("# signatures correctly identified", color='royalblue')
        ax2.tick_params(axis='y', labelcolor='royalblue')
        max_value = total_baseline_signatures_unique[pcap][0] if len(total_baseline_signatures_unique[pcap]) > 0 else 0
        ax2.set_ylim([0, max_value * 1.1])
        #ax2.set_yticks(range(0, int(max_value * 1.1) + 1, max(1, int(max_value / 5))))

        # Add a horizontal line delimiting the max value for the secondary Y-axis
        if len(total_baseline_signatures_unique[pcap]) > 0:
            ax2.axhline(y=total_baseline_signatures_unique[pcap][0], color='royalblue', linestyle='--', linewidth=1)
            ax2.text(len(x) - 1, total_baseline_signatures_unique[pcap][0], "baseline n. signatures", color='royalblue', fontsize=8, ha='right', va='bottom')

        # Title and layout
        plt.title(f"{pcap} ({nids_name.title()}, {dataset_name})")
        fig.tight_layout()

        # Save the graph
        output_dir = "graphs"
        os.makedirs(output_dir, exist_ok=True)
        nids_dataset_output_dir = f"{output_dir}/{dataset_name}_{nids_name}"
        os.makedirs(nids_dataset_output_dir, exist_ok=True)
        plt.savefig(f"{nids_dataset_output_dir}/{pcap}.png", dpi=300)
        plt.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate plots for NIDS analysis.")
    parser.add_argument("dataset_name", choices=["CICIDS2017", "CICIoT2023"], help="Dataset name (CICIDS2017 or CICIoT2023).")
    parser.add_argument("target_nids", choices=["snort", "suricata"], help="Target NIDS (snort or suricata).")

    args = parser.parse_args()
    line_graphs(args.dataset_name, args.target_nids, f"csv/{args.dataset_name}_{args.target_nids}.csv")
    bar_graphs(args.dataset_name, args.target_nids, f"csv/{args.dataset_name}_{args.target_nids}.csv")