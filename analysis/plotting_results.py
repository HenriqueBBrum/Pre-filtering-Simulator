import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

# Load data from a CSV file
data_file = 'results.csv'
data = pd.read_csv(data_file)
df = data[data['experiment'].isin(["PS N=5 T=25s", "PS N=25 T=10s", "PS N=50 T=5s", "Wang and Chang", "Our work"])]

metrics_name = [("suspicious_pkts_percent", "Packets forwarded to NIDS", "% of packets forwarded"), 
                ("signatures_true_positive_percent", "Signatures correctly identified", "% of signatures correctly identified")]
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
    handles = [handles[1], handles[0], handles[2], handles[4], handles[3]]
    labels = [labels[1], labels[0], labels[2], labels[4], labels[3]]

    plt.title(title)
    plt.ylabel(ylabel)
    plt.legend(title=None, handles=handles,labels=labels)
    plt.tight_layout()
    plt.savefig("graphs/"+metric+".png", dpi=300)

