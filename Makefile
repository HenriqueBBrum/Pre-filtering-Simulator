SNORT_COMMUNITY_RULES=etc/rules/snort3-community
SNORT3_REGISTERED_RULES=etc/rules/snortrules-snapshot-3000

SNORT_CONFIG=etc/configuration


ifndef EVAL_RULES
EVAL_RULES=$(SNORT_COMMUNITY_RULES)
endif


build:
	mkdir -p ${EXPERIMENTS_DIR} 

#	python3 -m cProfile -o temp.dat -s time src/main.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}  2>&1 | tee output/log_community.txt
simulation.community: 
	python3 src/main.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} community full 2>&1 | tee suspicious_packets/community/log.txt

simulation.registered:
	python3 src/main.py ${SNORT_CONFIG} ${SNORT3_REGISTERED_RULES} registered full 2>&1 |  tee suspicious_packets/registered/log.txt