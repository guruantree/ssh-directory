.PHONY: build test clean
PROFILE ?= default
REGION ?=

build:
	pip install cloudformation-cli-python-plugin
	cfn generate
	wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.3.21/openshift-client-linux-4.3.21.tar.gz -O src/awsqs_openshift_manager/oc.tgz
	cd src/awsqs_openshift_manager/ && tar -xvf oc.tgz && rm oc.tgz README.md kubectl && cd ../../
	cfn submit --dry-run
	zip -d awsqs-openshift-manager.zip src/awsqs_openshift_manager/oc

test:
	cfn generate
	cfn submit --dry-run
	sam local start-lambda

clean:
	rm -rf bin
	rm src/awsqs_openshift_manager/oc

