SNORT_COMMUNITY_RULES=etc/rules/snort3-community
SNORT3_REGISTERED_RULES=etc/rules/snort3-registered
SNORT3_REGISTERED_NO_ESTABLISHED_RULES=etc/rules/snort3-registered-no-established
SNORT_CONFIG=etc/configuration


OUTPUT_FOLDER=suspicious_pkts/


ifndef EVAL_RULES
EVAL_RULES=$(SNORT_COMMUNITY_RULES)
endif

ifndef SCENARIO
SCENARIO=full
endif	


#	python3 -m cProfile -o temp.dat -s time src/main.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}  2>&1 | tee suspicious_pkts/${SCENARIO}/registered/log.txt
simulation.community: 
	python3 src/main.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} community ${SCENARIO} 2>&1 |  tee suspicious_pkts/${SCENARIO}/community/log.txt

simulation.registered: clean build_registered
	python3 src/main.py ${SNORT_CONFIG} ${SNORT3_REGISTERED_RULES} registered ${SCENARIO} 2>&1 | tee suspicious_pkts/${SCENARIO}/registered/log.txt

clean:
	-rm -r suspicious_pkts/${SCENARIO}

build_registered:
	mkdir suspicious_pkts/${SCENARIO}
	mkdir suspicious_pkts/${SCENARIO}/registered