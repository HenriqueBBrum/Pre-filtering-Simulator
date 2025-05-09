import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import os
import argparse

from matplotlib.ticker import MaxNLocator

def experiments_new_alerts(df, dataset_name, nids_name, nids_dataset_output_dir):
    for metric in ["signatures_false_positive_percent", "signatures_false_positive_absolute"]:
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
            sorted_experiments = ["PS N=5 T=25s", "PS N=50 T=5s", "Fast pattern","Our work"]
            sorted_handles_labels = sorted(zip(handles, labels), key=lambda x: sorted_experiments.index(x[1]))
            handles, labels = zip(*sorted_handles_labels)

            if dataset_name == "CICIoT2023":
                plt.xticks(rotation=8, fontsize=9)

            plt.title(f"Signatures only in the experiments ({nids_name.title()}, {dataset_name})")
            metric_sign = "#"
            if "percent" in metric:
                metric_sign = "%"
            plt.ylabel(f"{metric_sign} new signatures")
            plt.legend(title=None, handles=handles, labels=labels)
            plt.tight_layout()

            # Save the graph for the current group
            if dataset_name == "CICIDS2017": 
                plt.savefig(f"{nids_dataset_output_dir}/experiment_only_signatures_{metric_sign}.png", dpi=300)
            else:
                plt.savefig(f"{nids_dataset_output_dir}/experiment_only_signatures__{metric_sign}_{int(i/5)}.png", dpi=300)
            plt.close()


def filteredXsignatures(df, dataset_name, nids_name, nids_dataset_output_dir, ):
    # Get unique values for "pkts_processed" and "total_baseline_signatures" for each "pcap"
    for pcap, group in df.groupby("pcap"):
        fig, axes = plt.subplots(1, 2, figsize=(15, 5))
        for idx, s in enumerate(["", "_flow"]):
            pkts_processed_unique = df.groupby("pcap")["pkts_processed"].unique()
            total_baseline_signatures_unique = df.groupby("pcap")["total_baseline_signatures"+s].unique()

            bar_width = 0.2
            x = range(len(group["experiment"]))

            # Sort the group by the specified experiment order
            experiment_order = ["PS N=5 T=25s", "PS N=50 T=5s", "Fast pattern", "Our work"]
            group = group.set_index("experiment").reindex(experiment_order).reset_index()

            # Bar graph for suspicious_pkts_absolute
            axes[idx].bar([i - bar_width / 2 for i in x], group["suspicious_pkts_absolute"], width=bar_width, color='coral', alpha=0.5, hatch='//', label="# suspicious packets")
            axes[idx].set_ylabel("# packets fowarded", color='coral')
            axes[idx].tick_params(axis='y', labelcolor='coral')
            axes[idx].set_xticks(x)
            axes[idx].set_xticklabels(group["experiment"], size=8)
            max_value = pkts_processed_unique[pcap][0] if len(pkts_processed_unique[pcap]) > 0 else 0

            # Add a horizontal line delimiting the max value for the primary Y-axis
            if max_value > 0:
                axes[idx].axhline(y=max_value, color='coral', linestyle='--', linewidth=1, label="Max suspicious packets")
                axes[idx].text(len(x) - 1, max_value, "# of baseline packets", color='coral', fontsize=8, ha='right', va='bottom')
                axes[idx].set_yticks(range(0, int(max_value) + 1, max(1, int(max_value // 5))))
                axes[idx].set_ylim([0, max_value*1.05])

            # Secondary y-axis for signatures_true_positive_absolute
            ax2 = axes[idx].twinx()
            ax2.bar([i + bar_width / 2 for i in x], group[f"signatures{s}_true_positive_absolute"], width=bar_width, color='royalblue', alpha=0.6, hatch='\\', label="# signatures correctly identified")
            ax2.set_ylabel(f"# signatures{s} correctly identified", color='royalblue')
            ax2.tick_params(axis='y', labelcolor='royalblue')
            ax2.yaxis.set_major_locator(MaxNLocator(integer=True))
            max_value = total_baseline_signatures_unique[pcap][0]
            ax2.set_ylim([0, 1])
            
            # Add a horizontal line delimiting the max value for the secondary Y-axis
            if max_value > 0:
                ax2.axhline(y=max_value, color='royalblue', linestyle='--', linewidth=1)
                ax2.text(len(x) - 1, max_value, f"# of baseline signatures{s}", color='royalblue', fontsize=8, ha='right', va='bottom')
                ax2.set_yticks(range(0, int(max_value) + 1, max(1, int(max_value // 5))))
                ax2.set_ylim([0, max_value*1.1])

            axes[idx].title.set_text(f"Signatures{s}")

        # Title and layout
        fig.suptitle(f"{pcap} ({nids_name.title()}, {dataset_name})")
        fig.tight_layout(w_pad=3.0)

        # Save the graph
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

    table_df = pd.DataFrame(table_data, columns=["Experiment"] + [f"{metric} ({name})" for metric in metrics for name in ("avg", "std")])
    table_df.to_csv(f"{nids_dataset_output_dir}/rules_comparison.csv", index=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate plots for NIDS analysis.")
    parser.add_argument("dataset_name", choices=["CICIDS2017", "CICIoT2023"], help="Dataset name (CICIDS2017 or CICIoT2023).")
    parser.add_argument("target_nids", choices=["snort", "suricata"], help="Target NIDS (snort or suricata).")

    args = parser.parse_args()

    output_dir = "graphs"
    os.makedirs(output_dir, exist_ok=True)
    nids_dataset_output_dir = f"{output_dir}/{args.dataset_name}_{args.target_nids}"
    os.makedirs(nids_dataset_output_dir, exist_ok=True)

    print(f"Generating graphs for {args.dataset_name} with {args.target_nids}...")
    data = pd.read_csv(f"csv/{args.dataset_name}_{args.target_nids}.csv")
    df = data[data['experiment'].isin(["packet_sampling_5_25", "packet_sampling_50_5", "pre_filtering_wang_chang","pre_filtering_full"])]
    # Update the experiment column with new names
    experiment_mapping = {
        "packet_sampling_5_25": "PS N=5 T=25s",
        "packet_sampling_50_5": "PS N=50 T=5s",
        "pre_filtering_wang_chang": "Fast pattern",
        "pre_filtering_full": "Our work"
    }
    df.loc[:, 'experiment'] = df['experiment'].map(experiment_mapping)

    experiments_new_alerts(df, args.dataset_name, args.target_nids, nids_dataset_output_dir)
    filteredXsignatures(df, args.dataset_name, args.target_nids, nids_dataset_output_dir)

    df = data[data['experiment'].isin(["pre_filtering_wang_chang", "pre_filtering_full"])]
    # Update the experiment column with new names
    experiment_mapping = {
        "pre_filtering_wang_chang": "Fast pattern",
        "pre_filtering_full": "Our work"
    }
    df.loc[:, 'experiment'] = df['experiment'].map(experiment_mapping)

    rules_comparison_table(df, nids_dataset_output_dir)