.PHONY: rules-dev study-phase2 phase1 phase2 phase3 phase4 ablation eval-check-locked prelock-check eval

ABLATION_MODE ?= --dry-run

# `eval` includes Phase 1's integrity/hash checks of read-only locked files.
# All detector, ablation, Phase 2-4, and rules-dev measurements use dev inputs only.
rules-dev:
	python -m eval.rules_dev_eval

study-phase2:
	python eval/phase2_eval.py

phase1:
	python eval/phase1_eval.py

phase2:
	python eval/phase2_eval.py --skip-model

phase3:
	python eval/phase3_eval.py $(PHASE3_ARGS)

phase4:
	python eval/phase4_eval.py $(PHASE4_ARGS)

ablation:
	python eval/ablation_eval.py $(ABLATION_MODE) $(ABLATION_ARGS)

eval-check-locked:
	python eval/check_locked_run.py

prelock-check:
	python eval/prelock_guard.py

eval:
	$(MAKE) eval-check-locked
	$(MAKE) phase1
	$(MAKE) phase2
	$(MAKE) rules-dev
	$(MAKE) phase3 PHASE3_ARGS="$(PHASE3_ARGS)"
	$(MAKE) phase4 PHASE4_ARGS="$(PHASE4_ARGS)"
	$(MAKE) ablation ABLATION_MODE="$(ABLATION_MODE)" ABLATION_ARGS="$(ABLATION_ARGS)"
