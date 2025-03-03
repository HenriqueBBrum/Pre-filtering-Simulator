pcap_folder=/home/hbeckerbrum/NFSDatasets/CICIDS2017/

for pcap in $pcap_folder*.pcap; do
    [ -e "$pcap" ] || continue
    name=${pcap##*/}
    name=${name%%.*}

    snort -c ../nids_configuration/snort_configuration/snort.lua --rule-path ../rules/snort3-registered/ -r $pcap -l full_pcap/ -A alert_json --lua "alert_json = {file = true}"
    mv "full_pcap/alert_json.txt" "full_pcap/snort/"$name".txt"

    suricata  -c ../nids_configuration/suricata_configuration/suricata.yaml -S ../rules/suricata-emerging/emerging-all.rules -r $pcap  -l full_pcap/
    mv "full_pcap/fast.log" "full_pcap/suricata/"$name".log"
done