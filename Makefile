SHELL = /bin/bash -c
VIRTUAL_ENV = $(shell poetry env info --path)
export BASH_ENV=$(VIRTUAL_ENV)/bin/activate

.DEFAULT_GOAL:=help
.PHONY: help
help:  ## Display this help
	$(info aws-securityhub-suppression - Supress SecurityHub findings through code)
	awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: lint
lint: _black _mypy ## Lint all project files

.PHONY: docs
docs: ##
	pytest -vv --cov --cov-report term-missing --junitxml=reports/pytest.xml --cov-report xml:reports/coverage.xml


.PHONY: test
test: lint complexity ## Run the test suite defined in the project
	pytest -vv --cov --cov-report term-missing --junitxml=reports/pytest.xml --cov-report xml:reports/coverage.xml

.PHONY: install
install: $(VIRTUAL_ENV) ## Install all dependencies
	poetry install

.PHONY: complexity-baseline
complexity: ## Perform complexity scanning
	$(info Maintenability index)
	radon mi --min A --max A --show --sort aws_network_firewall
	$(info Cyclomatic complexity index)
	xenon --max-absolute A --max-modules A --max-average A aws_network_firewall

.PHONY: _black
_black:
	$(info [*] Formatting python files...)
	black .

.PHONY: _mypy
_mypy:
	$(info [*] Python static type checker...)
	mypy --junit-xml reports/typecheck.xml aws_network_firewall

$(VERBOSE).SILENT:
