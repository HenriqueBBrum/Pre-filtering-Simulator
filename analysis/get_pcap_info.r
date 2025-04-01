library("rjson")
options(error = traceback)

args <- commandArgs(trailingOnly = TRUE)

specify_decimal <- function(x, k) trimws(format(round(x, k), nsmall=k))

pcap_names <- c("Monday-WorkingHours", "Tuesday-WorkingHours", "Wednesday-WorkingHours", "Thursday-WorkingHours", "Friday-WorkingHours")
dirs<-list.dirs(path = paste("../simulation_results/", args[1], sep=""), full.names = TRUE, recursive = FALSE)
rows<-(length(dirs)-1)*length(pcap_names)
count<-1

days <- c()
experiment <- c()

avg_num_rules_compared_to <- vector("double", length=rows)
avg_num_contents_compared_to <- vector("double", length=rows)
avg_num_pcre_compared_to <- vector("double", length=rows)
pkt_processing_time <- vector("double", length=rows)
suspicious_pkts_percent <- vector("double", length=rows)
signatures_true_positive_percent <- vector("double", length=rows)
nids_processing_time <- vector("double", length=rows)

for (pcap_name in pcap_names){
  for (dir in dirs){
    print(dir)
    json_file <- paste(dir, "analysis.json", sep="/")
    experiment_type<-sub(".*/", "", dir)
    if (file.exists(json_file)){
        json_data <- fromJSON(file=json_file)
        days <- append(days, sub("-.*", "", pcap_name))
        experiment <- append(experiment, experiment_type)

        if ("avg_num_rules_compared_to" %in% names(json_data[[pcap_name]])){
          avg_num_rules_compared_to[count] <- json_data[[pcap_name]]$avg_num_rules_compared_to
          avg_num_contents_compared_to[count] <- json_data[[pcap_name]]$avg_num_contents_compared_to
          avg_num_pcre_compared_to[count] <- json_data[[pcap_name]]$avg_num_pcre_compared_to          
        } else {
          avg_num_rules_compared_to[count] <- 0
          avg_num_contents_compared_to[count] <- 0
          avg_num_pcre_compared_to[count] <- 0
        }
        
        suspicious_pkts_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$number_of_suspicious_pkts/json_data[[pcap_name]]$pkts_processed), 2)
        signatures_true_positive_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$signatures_true_positive/json_data[[pcap_name]]$baseline_signatures), 2)

        nids_processing_time[count] <- json_data[[pcap_name]]$nids_processing_time 
        count<-count + 1
        print(count)
    }
  }
  print(nids_processing_time)


}

df <- data.frame( 
  day = days,
  experiment = experiment,
  avg_num_rules_compared_to = avg_num_rules_compared_to,
  avg_num_contents_compared_to = avg_num_contents_compared_to,
  avg_num_pcre_compared_to = avg_num_pcre_compared_to,
  suspicious_pkts_percent = suspicious_pkts_percent,
  signatures_true_positive_percent = signatures_true_positive_percent,
  nids_processing_time = nids_processing_time
)
write.csv(df,paste("new_res", "csv", sep="."))

