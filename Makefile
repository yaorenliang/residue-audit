PY ?= python3
COVERAGE_FLOOR ?= 88

.PHONY: all demo test cross cov verify docs-sample lab clean

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

# Coverage needs no dependency: the runner uses the stdlib trace module. The
# floor is a number in this file, so a drop is a red gate instead of a surprise.
cov:
	$(PY) tests/coverage.py --min $(COVERAGE_FLOOR)

verify: test cross cov
	@echo "VERIFY_OK"

# The README sample has to be captured, not hand-written: a hand-written sample
# drifts from as_text() the first time a column changes. This target prints the
# six demo sections the README quotes (section 1 verbatim), then the --json shape
# for the same tree, so a reader can diff instead of trusting.
# Both commands below are expected to report a verdict, so their exit code is
# checked rather than tolerated: the demo stands at fail (2), and so does the
# clean-tree trace (ctime and order are floors). A drift to any other code is a
# red target, which is the point of having it.
docs-sample:
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	$(PY) -m residue.demo || test $$? -eq 2; \
	echo '== --json =='; \
	$(PY) tests/build_tree.py "$$tmp/clean"; \
	$(PY) -m residue.cli trace "$$tmp/clean" --json || test $$? -eq 2

lab:
	sh lab/run.sh

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf out
