PYTHON ?= python
.PHONY: data train test serve screenshots report
data train test serve screenshots report:
	$(PYTHON) tasks.py $@
