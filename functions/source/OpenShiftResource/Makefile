.PHONY: build test clean
PROFILE ?= default
REGION ?=

build:
	pip install cloudformation-cli-python-plugin
	cfn generate
	cfn submit --dry-run

test:
	cfn generate
	cfn submit --dry-run
	sam local start-lambda

clean:
	rm -rf bin

