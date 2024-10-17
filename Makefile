EXPERIMENTS_DIR=experiments/memory_eval

SNORT_COMMUNITY_RULES=etc/rules/snort3-community
SNORT2_EMERGING_RULES=etc/rules/snort2-emerging
SNORT3_REGISTERED_RULES=etc/rules/snort3-registered

SNORT_CONFIG=etc/configuration
COMPILER_GOAL=etc/compiler_goal.json


ifndef EVAL_RULES
EVAL_RULES=$(SNORT_COMMUNITY_RULES)
endif

# Generates the strings used to name the output files of the memory usage evaluation
ifneq ($(filter simulation.memory_eval,$(MAKECMDGOALS)),)
MEM_PROFILE_NAME=$(basename $(notdir $(EVAL_RULES)))_mem_
NUM_OF_FILES=$(shell ls -dq $(EXPERIMENTS_DIR)/$(MEM_PROFILE_NAME)* | wc -l)
endif


build:
	mkdir -p ${EXPERIMENTS_DIR} 

#	python3 -m cProfile -o temp.dat -s time src/main.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}
simulation.community: 
	python3 -m cProfile -o temp.dat -s time  src/main.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}

simulation.registered:
	python3 src/main.py ${SNORT_CONFIG} ${SNORT3_REGISTERED_RULES} ${COMPILER_GOAL}

simulation.emerging: 
	python3 src/main.py ${SNORT_CONFIG} ${SNORT2_EMERGING_RULES} ${COMPILER_GOAL}

simulation.memory_eval:
	mprof run --python --output $(EXPERIMENTS_DIR)/$(MEM_PROFILE_NAME)$(NUM_OF_FILES).dat python3 \
	src/main.py  ${SNORT_CONFIG} ${EVAL_RULES} ${COMPILER_GOAL} 
