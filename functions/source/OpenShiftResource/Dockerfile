FROM python:3
WORKDIR /build
COPY requirements.txt Makefile .rpdk-config awsqs-openshift-manager.json /build/
COPY cloudformation_cli_python_lib /build/cloudformation_cli_python_lib/
COPY src /build/src/
RUN apt-get update && apt-get install zip && make build
CMD mkdir -p /output/ && mv /build/awsqs-openshift-manager.zip /output/