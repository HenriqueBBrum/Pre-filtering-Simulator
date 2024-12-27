pcap_folder=/home/hbeckerbrum/NFSDatasets/CICIDS2017/

for pcap in $pcap_folder*.pcap; do
    [ -e "$pcap" ] || continue
    name=${pcap##*/}
    name=${name%%.*}

    snort -c ../snort_configuration/snort.lua --rule-path ../rules/snort3-registered/ -r $pcap -l full_pcap/ -A alert_json --lua "alert_json = {file = true}"
    mv "full_pcap/alert_json.txt" "full_pcap/"$name".txt"
done