pcap_folder=/home/hbeckerbrum/NFSDatasets/CICIDS2017/
log_dir=/home/hbeckerbrum/Pre-filtering-Simulator/etc/alerts/

snort_conf_file=../nids_configuration/snort/snort.lua
suricata_conf_file=../nids_configuration/suricata/suricata.yaml

for pcap in $pcap_folder*.pcap; do
    [ -e "$pcap" ] || continue
    name=${pcap##*/}
    name=${name%%.*}

    snort -c $snort_conf_file --rule-path ../rules/snort3-registered/ -r $pcap -l $log_dir -A alert_json --lua "alert_json = {file = true}"
    mv $log_dir"alert_json.txt" $log_dir$name".txt"

    suricata  -c $conf_file -S ../rules/suricata-emerging/emerging-all.rules -r $pcap -l $log_dir
    mv $log_dir"fast.log" $log_dir$name".log"
done