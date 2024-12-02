PRE-FILTERING_CONFIG=etc/simulation_configuration/pre_filtering.json
FLOW_SAMPLING_CONFIG=etc/simulation_configuration/flow_sampling.json


#	python3 -m cProfile -o temp.dat -s time src/main.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}  2>&1 | tee suspicious_pkts/${SCENARIO}/registered/log.txt
simulation.pre-filtering:
	python3 src/main.py ${FILTERING_CONFIG}

simulation.flow_sampling:
	python3 src/main.py ${FLOW_SAMPLING_CONFIG}

clean:
	-rm -r simulation_results/*
