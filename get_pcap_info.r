library("rjson")

pcap_name = "Wednesday_end"

dirs<-list.dirs(path = "simulation_results", full.names = TRUE, recursive = FALSE)

id<-character()
ptk_processing_time <- vector("double", length=length(dirs))
suspicious_pkts_percent <- vector("double", length=length(dirs))

pkt_alerts_true_positives_percent <- vector("double", length=length(dirs))
pkt_alerts_false_negatives_percent <- vector("double", length=length(dirs))
flow_alerts_true_positives_percent <- vector("double", length=length(dirs))
flow_alerts_false_negatives_percent <- vector("double", length=length(dirs))

snort_processing_time <- vector("double", length=length(dirs))

count = 1
for (dir in dirs){
    json_file <- paste(dir, "analysis.json", sep="/")
    experiment_type<-sub(".*/", "", dir)
    id <- append(id, experiment_type)

    if (file.exists(json_file)){
        print(experiment_type)
        json_data <- fromJSON(file=json_file)
        
        ptk_processing_time[count] <- json_data[[pcap_name]]$avg_pkt_processing_time

        suspicious_pkts_percent[count] <- 100*(json_data[[pcap_name]]$number_of_suspicious_pkts/json_data[[pcap_name]]$pkts_processed)
        
        pkt_alerts_true_positives_percent[count] <- 100*(json_data[[pcap_name]]$pkt_alerts_true_positive/json_data[[pcap_name]]$baseline_pkt_alerts)
        pkt_alerts_false_negatives_percent[count] <- 100*(json_data[[pcap_name]]$pkt_alerts_false_negative/json_data[[pcap_name]]$baseline_pkt_alerts)

        flow_alerts_true_positives_percent[count] <- 100*(json_data[[pcap_name]]$flow_alerts_true_positive/json_data[[pcap_name]]$baseline_flow_alerts)
        flow_alerts_false_negatives_percent[count] <- 100*(json_data[[pcap_name]]$flow_alerts_false_negative/json_data[[pcap_name]]$baseline_flow_alerts)

        snort_processing_time[count] <- json_data[[pcap_name]]$snort_processing_time 
    }
    count = count + 1
}

df <- data.frame(
  id = id,
  ptk_processing_time = ptk_processing_time,
  suspicious_pkts_percent = suspicious_pkts_percent,
  pkt_alerts_true_positives_percent = pkt_alerts_true_positives_percent,
  pkt_alerts_false_negatives_percent = pkt_alerts_false_negatives_percent,
  flow_alerts_true_positives_percent = flow_alerts_true_positives_percent,
  flow_alerts_false_negatives_percent = flow_alerts_false_negatives_percent,
  snort_processing_time = snort_processing_time

)
print(df)
write.csv(df,paste(pcap_name, "csv", sep="."))