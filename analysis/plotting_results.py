import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import os
import argparse

def main(nids_name, dataset_name, csv_filepath):
    # Load data from the specified CSV file
    data = pd.read_csv(csv_filepath)
    #df = data[data['experiment'].isin(["PS N=5 T=25s", "PS N=25 T=10s", "PS N=50 T=5s", "Wang and Chang", "Our work"])]
    df = data[data['experiment'].isin(["packet_sampling_50_5", "packet_sampling_10_5", "pre_filtering_wang_chang", "pre_filtering_full"])]
    metrics_name = [("suspicious_pkts_percent", "Packets forwarded to NIDS", "% of packets forwarded"), 
                    ("signatures_true_positive_percent", "Signatures correctly identified", "% of signatures correctly identified"),
                     ("signatures_false_positive_percent", "Signatures not in baseline", "% of false positive signatures")]
                    #("pkt_processing_time", "Simulator avg. pkt. processing time", "seconds"), ("snort_processing_time", "Snort processing time", "seconds")]
    for metric, title, ylabel in metrics_name:
        metric_df = df[["day", "experiment", metric]]
        plot_df = metric_df.pivot_table(index='day', columns='experiment', values=metric, sort=False)
        print(plot_df)
        plot = plot_df.plot(kind='line', style = ['o--','v--','s-', 'x-', 'p-'], xlabel='')
        if "percent" in metric:
            plt.gca().yaxis.set_major_formatter(mtick.PercentFormatter(xmax=100))
            ax = plt.gca()
            ax.set_ylim([0, 100])
        # elif metric == "pkt_processing_time":
        #     plt.yscale("log")
        #     plt.ylim(0.00001, 0.01)
        else:
            plt.gca().yaxis.set_major_formatter(mtick.StrMethodFormatter('{x}s'))

        handles,labels = plt.gca().get_legend_handles_labels()

        # Change order so that our work is the last one on the legend
        # handles = [handles[1], handles[0], handles[2]]#, handles[4], handles[3]]
        # labels = [labels[1], labels[0], labels[2]]#, labels[4], labels[3]]

        plt.title(f"{title} ({nids_name.title()}, {dataset_name})")
        plt.ylabel(ylabel)
        plt.legend(title=None, handles=handles,labels=labels)
        plt.tight_layout()

        # Create output directory if it doesn't exist
        output_dir = "graphs"
        os.makedirs(output_dir, exist_ok=True)

        plt.savefig(f"{output_dir}/{metric}_{nids_name}_{dataset_name}.png", dpi=300)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate plots for NIDS analysis.")
    parser.add_argument("target_nids", choices=["snort", "suricata"], help="Target NIDS (snort or suricata).")
    parser.add_argument("dataset_name", choices=["CICIDS2017", "CICIoT2023"], help="Dataset name (CICIDS2017 or CICIoT2023).")
    parser.add_argument("csv_filepath", type=str, help="Path to the CSV file containing the results.")

    args = parser.parse_args()
    main(args.target_nids, args.dataset_name, args.csv_filepath)
