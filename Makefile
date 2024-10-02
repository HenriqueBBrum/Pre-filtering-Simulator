COMPILER_EXPERIMENTS_DIR=experiments/memory_eval

SNORT_COMMUNITY_RULES=etc/rules/snort3-community
SNORT2_EMERGING_RULES=etc/rules/snort2-emerging
SNORT3_REGISTERED_RULES=etc/rules/snort3-registered

SNORT_CONFIG=etc/configuration
COMPILER_GOAL=etc/compiler_goal.json


ifndef EVAL_RULES
EVAL_RULES=$(SNORT_COMMUNITY_RULES)
endif

# Generates the strings used to name the output files of the execution time evaluation
ifneq ($(filter compiler.time_eval,$(MAKECMDGOALS)),)
TIME_PROFILE_NAME=$(basename $(notdir $(EVAL_RULES)))_time_
NUM_OF_FILES=$(shell ls -dq $(COMPILER_EXPERIMENTS_DIR)/$(TIME_PROFILE_NAME)* | wc -l)
endif

# Generates the strings used to name the output files of the memory usage evaluation
ifneq ($(filter compiler.memory_eval,$(MAKECMDGOALS)),)
MEM_PROFILE_NAME=$(basename $(notdir $(EVAL_RULES)))_mem_
NUM_OF_FILES=$(shell ls -dq $(COMPILER_EXPERIMENTS_DIR)/$(MEM_PROFILE_NAME)* | wc -l)
endif


build:
	mkdir -p ${COMPILER_EXPERIMENTS_DIR} 

compiler.community: 
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT_COMMUNITY_RULES} ${COMPILER_GOAL}

compiler.registered:
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT3_REGISTERED_RULES} ${COMPILER_GOAL}

compiler.emerging: 
	python3 src/compiler/compiler.py ${SNORT_CONFIG} ${SNORT2_EMERGING_RULES} ${COMPILER_GOAL}

compiler.memory_eval:
	mprof run --python --output $(COMPILER_EXPERIMENTS_DIR)/$(MEM_PROFILE_NAME)$(NUM_OF_FILES).dat python3 \
	src/compiler/compiler.py  ${SNORT_CONFIG} ${EVAL_RULES} ${COMPILER_GOAL} 
