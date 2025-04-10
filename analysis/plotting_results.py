import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import os
import argparse

def main(dataset_name, nids_name, csv_filepath):
    # Load data from the specified CSV file
    data = pd.read_csv(csv_filepath)
    df = data[data['experiment'].isin(["packet_sampling_10_25", "packet_sampling_50_5", "pre_filtering_wang_chang", "pre_filtering_full"])]
    # Update the experiment column with new names
    experiment_mapping = {
        "packet_sampling_10_25": "PS N=10 T=25s",
        "packet_sampling_50_5": "PS N=50 T=5s",
        "pre_filtering_wang_chang": "Fast pattern",
        "pre_filtering_full": "Our work"
    }
    df['experiment'] = df['experiment'].map(experiment_mapping)
    metrics_name = [("suspicious_pkts_percent", "Packets forwarded to NIDS", "% of packets forwarded"), 
                    ("signatures_true_positive_percent", "Signatures correctly identified", "% of signatures correctly identified"),
                     ("signatures_false_positive_percent", "Signatures only in the experiments", "% of new signatures")]
                    #("pkt_processing_time", "Simulator avg. pkt. processing time", "seconds"), ("snort_processing_time", "Snort processing time", "seconds")]
    for metric, title, ylabel in metrics_name:
        metric_df = df[["pcap", "experiment", metric]]
        plot_df = metric_df.pivot_table(index='pcap', columns='experiment', values=metric, sort=False)
        # Group the PCAPs into chunks of 5 and plot each group
        for i in range(0, len(plot_df), 5):
            group_df = plot_df.iloc[i:i+5]
            print(group_df)
            if dataset_name == "CICIDS2017":
                group_df.index = pd.Categorical(plot_df.index, categories=["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"], ordered=True)
                group_df = group_df.sort_index()

            group_plot = group_df.plot(kind='line', style=['o--', 'v--', 's-', 'x-', 'p-'], xlabel='')
            if "percent" in metric:
                plt.gca().yaxis.set_major_formatter(mtick.PercentFormatter(xmax=100))
                ax = plt.gca()
                ax.set_ylim([-5, 105])

            handles, labels = plt.gca().get_legend_handles_labels()
            sorted_experiments = ["PS N=10 T=25s", "PS N=50 T=5s", "Fast pattern", "Our work"]
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate plots for NIDS analysis.")
    parser.add_argument("dataset_name", choices=["CICIDS2017", "CICIoT2023"], help="Dataset name (CICIDS2017 or CICIoT2023).")
    parser.add_argument("target_nids", choices=["snort", "suricata"], help="Target NIDS (snort or suricata).")

    args = parser.parse_args()
    main(args.dataset_name, args.target_nids, f"csv/{args.dataset_name}_{args.target_nids}.csv")
