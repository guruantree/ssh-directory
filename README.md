# quickstart-redhat-openshift
## Red Hat OpenShift Container Platform on the AWS Cloud


This Quick Start deploys Red Hat OpenShift Container Platform on the AWS Cloud in a highly available configuration.

Red Hat OpenShift Container Platform is a platform as a service (PaaS) solution that is based on Docker-formatted Linux containers, Google Kubernetes orchestration, and the Red Hat Enterprise Linux (RHEL) operating system.

The Quick Start includes AWS CloudFormation templates that build the AWS infrastructure using AWS best practices, and then pass that environment to Ansible playbooks to build out the OpenShift environment. The deployment provisions OpenShift master instances, etcd instances, and node instances in a virtual private cloud (VPC) across three Availability Zones.

The Quick Start offers two deployment options:

- Deploying OpenShift Container Platform into a new VPC
- Deploying OpenShift Container Platform into an existing VPC

You can also use the AWS CloudFormation templates as a starting point for your own implementation.

![Quick Start architecture for OpenShift Enterprise on AWS](https://d0.awsstatic.com/partner-network/QuickStart/datasheets/redhat-openshift-on-aws-architecture.png)

For architectural details, best practices, step-by-step instructions, and customization options, see the [deployment guide](https://s3.amazonaws.com/quickstart-reference/redhat/openshift/latest/doc/red-hat-openshift-on-the-aws-cloud.pdf).

To post feedback, submit feature ideas, or report bugs, use the **Issues** section of this GitHub repo.
If you'd like to submit code for this Quick Start, please review the [AWS Quick Start Contributor's Kit](https://aws-quickstart.github.io/). 
