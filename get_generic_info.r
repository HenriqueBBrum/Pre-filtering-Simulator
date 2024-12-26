library("rjson")


dirs<-list.dirs(path = "simulation_results", full.names = TRUE, recursive = FALSE)

id<-character()
memory_usage <- vector("double", length=length(dirs))
simulation_time <- vector("double", length=length(dirs))
count = 1
for (dir in dirs){
    json_file <- paste(dir, "analysis.json", sep="/")
    experiment_type<-sub(".*/", "", dir)
    id <- append(id, experiment_type)

    if (file.exists(json_file)){
        print(experiment_type)
        json_data <- fromJSON(file=json_file)
        if (is.null(json_data$payload_size_MB)) {
            memory_usage[count] <- 0
        }else{
            memory_usage[count] <- json_data$payload_size_MB
        }
        simulation_time[count] <- json_data$total_execution_time
    }
    count = count + 1
}

df <- data.frame(
  id = id,
  memory_usage = memory_usage,
  simulation_time = simulation_time
)
print(df)