.PHONY: rules-dev study-phase2 phase3 phase4 eval

# Dev-only targets. No target reads test/held-out data or starts Phase 5.
rules-dev:
	python -m eval.rules_dev_eval

study-phase2:
	python eval/phase2_eval.py

phase3:
	python eval/phase3_eval.py

phase4:
	python eval/phase4_eval.py

eval: rules-dev phase3 phase4
