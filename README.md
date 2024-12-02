# Optmized-pre-filtering-for-NIDS


snort -c ../etc/configuration/snort.lua --rule-path ../etc/rules/snort3-registered/ -r /home/hbeckerbrum/NFSDatasets/CICIDS2017/Wednesday-WorkingHours.pcap -l . -A alert_json --lua "alert_json = {file = true}"


snortrules-snapshot-3000 -  date?



Folder containing the experiments' results

- 'first' uses only the first content of each rule
- 'first_last' uses the first and last content of each rule
- 'first_second' uses the first and second content of each rule
- 'header_only' uses only the header realted keys
- 'content_only' uses only the content or pcre keyword
- 'full' uses all supported packet header fields, and content and PCRE matching
- 'longest' uses all supported packet header fields, and the longest content or PCRE entry