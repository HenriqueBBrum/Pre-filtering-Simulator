if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <dataset_name>"
    echo "Dataset name must be either CICIoT2023 or CICIDS2017"
    exit 1
fi

dataset_name=$1

if [ "$dataset_name" != "CICIoT2023" ] && [ "$dataset_name" != "CICIDS2017" ]; then
    echo "Invalid dataset name. Must be either CICIoT2023 or CICIDS2017"
    exit 1
fi

pcap_folder="/home/hbeckerbrum/NFSDatasets/${dataset_name}/"

script_dir=$(dirname "$(realpath "$0")")

log_dir="${script_dir}/${dataset_name}/alerts"
snort_conf_file="${script_dir}/${dataset_name}/nids_configuration/snort/snort.lua"
suricata_conf_file="${script_dir}/${dataset_name}/nids_configuration/suricata/suricata.yaml"

mkdir -p "$log_dir"
mkdir -p "$log_dir/snort"
mkdir -p "$log_dir/suricata"

for pcap in $pcap_folder*.pcap; do
    [ -e "$pcap" ] || continue
    name=${pcap##*/}
    name=${name%%.*}

    snort -c $snort_conf_file --rule-path "${script_dir}/rules/snort3-registered/" -r $pcap -l $log_dir -A alert_json --lua "alert_json = {file = true}"
    mv "${log_dir}/alert_json.txt" "${log_dir}/snort/${name}.txt"

    suricata  -c $suricata_conf_file -S "${script_dir}/rules/suricata-emerging/emerging-all.rules" -r $pcap -l $log_dir
    mv "${log_dir}/fast.log" "${log_dir}/suricata/${name}.log"
done