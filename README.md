# Optmized-pre-filtering-for-NIDS


snort -c ../configuration/snort.lua --rule-path ../rules/snortrules-snapshot-3000/rules/ -r /home/hbeckerbrum/NFSDatasets/CICIDS2017/Wednesday-WorkingHours.pcap -l . -A alert_json --lua "alert_json = {file = true}"