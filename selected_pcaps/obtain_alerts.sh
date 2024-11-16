pcap_folder=pcaps/

for pcap in $pcap_folder*.pcap; do
    [ -e "$pcap" ] || continue
    name=${pcap##*/}
    name=${name%%.*}

    snort -c ../etc/configuration/snort.lua --rule-path ../etc/rules/snort3-registered/ -r $pcap -l alerts_registered/ -A alert_json --lua "alert_json = {file = true}"
    mv "alerts_registered/alert_json.txt" "alerts_registered/"$name".txt"
done