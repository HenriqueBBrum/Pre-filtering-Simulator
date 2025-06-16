# Read over all the simulator results and collected the plotting information for each dataset and NIDS combination

library("rjson")
options(error = traceback)

specify_decimal <- function(x, k) trimws(format(round(x, k), nsmall=k))

for (datset in c("CICIDS2017", "CICIoT2023")) {
  for (nids_name in c("snort", "suricata")) {
    exp_folder_path = paste("../simulation_results/", datset, "/", nids_name, sep="")
    if (!dir.exists(exp_folder_path)) {
      stop(paste("The directory", exp_folder_path, "does not exist."))
    }
    dirs <- list.dirs(path = exp_folder_path, full.names = TRUE, recursive = FALSE)
    dirs <- dirs[sapply(dirs, function(d) any(grepl("\\.json$", list.files(d, full.names = TRUE))))]

    if (length(dirs) > 0) {
      pcap_names <- list.files(path = dirs[1], pattern = "\\.log$", full.names = FALSE)
    } else {
      exit("No directories found.")
    }
    pcap_names <- sub("\\.log$", "", pcap_names)

    rows<-(length(dirs)-1)*length(pcap_names)
    count<-1
    
    pcaps <- c()
    pkts_processed <- c()
    total_baseline_alerts <- c()
    total_experiment_alerts <- c()
    experiment <- c()

    avg_num_rules_compared_to <- vector("double", length=rows)
    avg_num_contents_compared_to <- vector("double", length=rows)
    avg_num_pcre_compared_to <- vector("double", length=rows)
    pkt_processing_time <- vector("double", length=rows)

    pkts_filtered_percent <- vector("double", length=rows)
    pkts_filtered_absolute <- vector("double", length=rows)

    pkts_fowarded_percent <- vector("double", length=rows)
    pkts_fowarded_absolute <- vector("double", length=rows)

    alerts_true_positive_percent <- vector("double", length=rows)
    alerts_true_positive_absolute <- vector("double", length=rows)

    alerts_false_positive_percent <- vector("double", length=rows)
    alerts_false_positive_absolute <- vector("double", length=rows)

    nids_processing_time <- vector("double", length=rows)

    for (pcap_name in pcap_names){
      pcap_cleaned_name <- sub("-WorkingHours", "", pcap_name)
      for (dir in dirs){
        json_file <- paste(dir, "analysis.json", sep="/")
        experiment_type<-sub(".*/", "", dir)
        if (file.exists(json_file)){
            json_data <- fromJSON(file=json_file)
            pcaps <- append(pcaps, pcap_cleaned_name)
            pkts_processed <- append(pkts_processed, json_data[[pcap_name]]$pkts_processed)
            total_baseline_alerts <- append(total_baseline_alerts, json_data[[pcap_name]]$baseline_alerts)
            total_experiment_alerts <- append(total_experiment_alerts, json_data[[pcap_name]]$experiment_alerts)

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

            pkts_fowarded_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$pkts_fowarded/json_data[[pcap_name]]$pkts_processed), 2)
            pkts_fowarded_absolute[count] <- json_data[[pcap_name]]$pkts_fowarded

            alerts_true_positive_absolute[count] <-json_data[[pcap_name]]$alerts_true_positive
            if (json_data[[pcap_name]]$baseline_alerts == 0) {
              alerts_true_positive_percent[count] <- 100
            } else {
              alerts_true_positive_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$alerts_true_positive/json_data[[pcap_name]]$baseline_alerts), 2)
            }

            alerts_false_positive_absolute[count] <-json_data[[pcap_name]]$alerts_false_positive
            if (json_data[[pcap_name]]$experiment_alerts == 0) {
              alerts_false_positive_percent[count] <- 0
            } else {
              alerts_false_positive_percent[count] <- specify_decimal(100*(json_data[[pcap_name]]$alerts_false_positive/json_data[[pcap_name]]$experiment_alerts), 2)
            }

            nids_processing_time[count] <- json_data[[pcap_name]]$nids_processing_time 
            count<-count + 1
        }
      }
    }

    df <- data.frame( 
      pcap = pcaps,
      experiment = experiment,
      pkts_processed = pkts_processed,
      total_baseline_alerts = total_baseline_alerts,
      total_experiment_alerts = total_experiment_alerts,
      avg_num_rules_compared_to = avg_num_rules_compared_to,
      avg_num_contents_compared_to = avg_num_contents_compared_to,
      avg_num_pcre_compared_to = avg_num_pcre_compared_to,
      pkts_fowarded_percent = pkts_fowarded_percent,
      pkts_fowarded_absolute = pkts_fowarded_absolute,
      alerts_true_positive_percent = alerts_true_positive_percent,
      alerts_true_positive_absolute = alerts_true_positive_absolute,
      alerts_false_positive_percent = alerts_false_positive_percent,
      alerts_false_positive_absolute = alerts_false_positive_absolute,
      nids_processing_time = nids_processing_time
    )
    write.csv(df,paste("csv/",datset,"_",nids_name, ".csv", sep=""))
  }
}


