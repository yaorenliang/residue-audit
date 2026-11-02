PY ?= python3

.PHONY: all demo test cross verify lab clean

all: verify

demo:
	$(PY) -m residue.demo

test:
	$(PY) -m unittest discover -s tests -t . -v

cross:
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	$(PY) tests/build_tree.py "$$tmp/aligned"; \
	$(PY) tests/build_tree.py "$$tmp/dirty" --no-align; \
	echo "== aligned =="; sh tests/cross_check.sh "$$tmp/aligned"; \
	echo "== dirty =="; sh tests/cross_check.sh "$$tmp/dirty"

verify: test cross
	@echo "VERIFY_OK"

lab:
	sh lab/run.sh

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf out
