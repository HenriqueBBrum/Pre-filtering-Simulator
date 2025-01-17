library("rjson")

specify_decimal <- function(x, k) trimws(format(round(x, k), nsmall=k))

pcap_names <- c("Monday-WorkingHours", "Tuesday-WorkingHours", "Wednesday-WorkingHours", "Thursday-WorkingHours", "Friday-WorkingHours")
dirs<-list.dirs(path = "../simulation_results", full.names = TRUE, recursive = FALSE)
rows<-(length(dirs)-1)*length(pcap_names)
count<-1

days <- c()
experiment <- c()
pkt_processing_time <- vector("double", length=rows)
suspicious_pkts_percent <- vector("double", length=rows)
pkt_alerts_true_positives_percent <- vector("double", length=rows)
flow_alerts_true_positives_percent <- vector("double", length=rows)
snort_processing_time <- vector("double", length=rows)

for (pcap_name in pcap_names){
  for (dir in dirs){
      json_file <- paste(dir, "analysis.json", sep="/")
      experiment_type<-sub(".*/", "", dir)

      if (file.exists(json_file)){
          print(experiment_type)
          json_data <- fromJSON(file=json_file)
          days <- append(days, sub("-.*", "", pcap_name))
          experiment <- append(experiment, experiment_type)
          pkt_processing_time[count] <- json_data[[pcap_name]]$avg_pkt_processing_time
          suspicious_pkts_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$number_of_suspicious_pkts/json_data[[pcap_name]]$pkts_processed), 2)
          
          pkt_alerts_true_positives_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$pkt_alerts_true_positive/json_data[[pcap_name]]$baseline_pkt_alerts), 2)

          flow_alerts_true_positives_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$flow_alerts_true_positive/json_data[[pcap_name]]$baseline_flow_alerts), 2)

          snort_processing_time[count] <- json_data[[pcap_name]]$snort_processing_time 
          count<-count + 1
      }
  }

}

df <- data.frame( 
  day = days,
  experiment = experiment,
  suspicious_pkts_percent = suspicious_pkts_percent,
  pkt_alerts_true_positives_percent = pkt_alerts_true_positives_percent,
  flow_alerts_true_positives_percent = flow_alerts_true_positives_percent,
  pkt_processing_time = pkt_processing_time,
  snort_processing_time = snort_processing_time
)
write.csv(df,paste("results", "csv", sep="."))

