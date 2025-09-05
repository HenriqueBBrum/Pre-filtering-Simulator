# Obtain the baseline alerts for a NIDS with the desired configuration

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <dataset_name> <pcap_folder>"
    echo "Dataset name must be either CICIDS2017 or CICIoT2023"
    exit 1
fi

dataset_name="$1"
pcap_folder="$2/$dataset_name/"

if [ "$dataset_name" != "CICIDS2017" ] && [ "$dataset_name" != "CICIoT2023" ]; then
    echo "Invalid dataset name. Must be either CICIDS2017 or CICIoT2023"
    exit 1
fi

script_dir=$(dirname "$(realpath "$0")")

log_dir="${script_dir}/${dataset_name}/alerts"
snort_conf_file="${script_dir}/${dataset_name}/nids_configuration/snort/snort.lua"

mkdir -p "$log_dir"
mkdir -p "$log_dir/snort"

for pcap in $pcap_folder*.pcap; do
    echo $pcap
    [ -e "$pcap" ] || continue
    name=${pcap##*/}
    name=${name%%.*}

    snort -c $snort_conf_file --rule-path "${script_dir}/rules/snort3-registered/" -r $pcap -l $log_dir -A alert_json --lua "alert_json = {file = true}"
    #mv "${log_dir}/alert_json.txt" "${log_dir}/snort/${name}.log"
done