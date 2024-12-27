library("rjson")

specify_decimal <- function(x, k) trimws(format(round(x, k), nsmall=k))

pcap_name = "Friday_mid"

dirs<-list.dirs(path = "simulation_results", full.names = TRUE, recursive = FALSE)

id<-character()
ptk_processing_time <- vector("double", length=length(dirs))
suspicious_pkts_percent <- vector("double", length=length(dirs))

pkt_alerts_true_positives_percent <- vector("double", length=length(dirs))
flow_alerts_true_positives_percent <- vector("double", length=length(dirs))

snort_processing_time <- vector("double", length=length(dirs))

count = 1
for (dir in dirs){
    json_file <- paste(dir, "analysis.json", sep="/")
    experiment_type<-sub(".*/", "", dir)

    if (file.exists(json_file)){
        id <- append(id, experiment_type)

        print(experiment_type)
        json_data <- fromJSON(file=json_file)
        
        ptk_processing_time[count] <- json_data[[pcap_name]]$avg_pkt_processing_time

        
        suspicious_pkts_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$number_of_suspicious_pkts/json_data[[pcap_name]]$pkts_processed), 2)
        
        pkt_alerts_true_positives_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$pkt_alerts_true_positive/json_data[[pcap_name]]$baseline_pkt_alerts), 2)

        flow_alerts_true_positives_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$flow_alerts_true_positive/json_data[[pcap_name]]$baseline_flow_alerts), 2)

        snort_processing_time[count] <- json_data[[pcap_name]]$snort_processing_time 
    }
    count = count + 1
}

df <- data.frame(
  id = id,
  suspicious_pkts_percent = suspicious_pkts_percent,
  pkt_alerts_true_positives_percent = pkt_alerts_true_positives_percent,
  flow_alerts_true_positives_percent = flow_alerts_true_positives_percent,
  ptk_processing_time = ptk_processing_time,
  snort_processing_time = snort_processing_time

)
write.csv(df,paste(pcap_name, "csv", sep="."))