library("rjson")
options(error = traceback)

args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2 || !(args[1] %in% c("CICIDS2017", "CICIoT2023") || !(args[2] %in% c("snort", "suricata")))) {
  stop("Usage: Rscript get_pcap_info.r <dataset: CICIDS2017|CICIoT2023> <nids_name: snort|suricata>")
}
specify_decimal <- function(x, k) trimws(format(round(x, k), nsmall=k))

exp_folder_path = paste("../simulation_results/", args[1], "/", args[2], sep="")
if (!dir.exists(exp_folder_path)) {
  stop(paste("The directory", exp_folder_path, "does not exist."))
}
dirs <- list.dirs(path = exp_folder_path, full.names = TRUE, recursive = FALSE)

if (length(dirs) > 0) {
  pcap_names <- list.files(path = dirs[1], pattern = "\\.log$", full.names = FALSE)
} else {
  exit("No directories found.")
}
pcap_names <- sub("\\.log$", "", pcap_names)

rows<-(length(dirs)-1)*length(pcap_names)
count<-1
pcaps <- c()
experiment <- c()

avg_num_rules_compared_to <- vector("double", length=rows)
avg_num_contents_compared_to <- vector("double", length=rows)
avg_num_pcre_compared_to <- vector("double", length=rows)
pkt_processing_time <- vector("double", length=rows)
suspicious_pkts_percent <- vector("double", length=rows)
signatures_true_positive_percent <- vector("double", length=rows)
signatures_false_positive_percent <- vector("double", length=rows)
nids_processing_time <- vector("double", length=rows)

for (pcap_name in pcap_names){
  pcap_cleaned_name <- sub("-WorkingHours", "", pcap_name)
  print(pcap_name)
  for (dir in dirs){
    json_file <- paste(dir, "analysis.json", sep="/")
    experiment_type<-sub(".*/", "", dir)
    if (file.exists(json_file)){
        json_data <- fromJSON(file=json_file)
        pcaps <- append(pcaps, pcap_cleaned_name)
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
        if (json_data[[pcap_name]]$baseline_signatures == 0) {
          signatures_true_positive_percent[count] <- 100
        } else {
          signatures_true_positive_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$signatures_true_positive/json_data[[pcap_name]]$baseline_signatures), 2)
        }
        if (json_data[[pcap_name]]$experiment_signatures == 0) {
          signatures_false_positive_percent[count] <- 0
        } else {
          signatures_false_positive_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$signatures_false_positive/json_data[[pcap_name]]$experiment_signatures), 2)
        }

        nids_processing_time[count] <- json_data[[pcap_name]]$nids_processing_time 
        count<-count + 1
    }
  }
  print(nids_processing_time)
}

df <- data.frame( 
  pcap = pcaps,
  experiment = experiment,
  avg_num_rules_compared_to = avg_num_rules_compared_to,
  avg_num_contents_compared_to = avg_num_contents_compared_to,
  avg_num_pcre_compared_to = avg_num_pcre_compared_to,
  suspicious_pkts_percent = suspicious_pkts_percent,
  signatures_true_positive_percent = signatures_true_positive_percent,
  signatures_false_positive_percent = signatures_false_positive_percent,
  nids_processing_time = nids_processing_time
)
write.csv(df,paste("csv/",args[1],"_",args[2], ".csv", sep=""))

