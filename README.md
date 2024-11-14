# Optmized-pre-filtering-for-NIDS


snort -c ../etc/configuration/snort.lua --rule-path ../etc/rules/snortrules-snapshot-3000/ -r /home/hbeckerbrum/NFSDatasets/CICIDS2017/Wednesday-WorkingHours.pcap -l . -A alert_json --lua "alert_json = {file = true}"