# quickstart-redhat-openshift
## Red Hat OpenShift Container Platform on the AWS Cloud


This Quick Start deploys Red Hat OpenShift Container Platform on the AWS Cloud in a highly available configuration.

Red Hat OpenShift Container Platform is a platform as a service (PaaS) solution that is based on Docker-formatted Linux containers, Google Kubernetes orchestration, and the Red Hat Enterprise Linux (RHEL) operating system.

The Quick Start includes AWS CloudFormation templates that build the AWS infrastructure using AWS best practices, and then pass that environment to Ansible playbooks to build out the OpenShift environment. The deployment provisions OpenShift master instances, etcd instances, and node instances in a virtual private cloud (VPC) across three Availability Zones.

The Quick Start offers two deployment options:

- Deploying OpenShift Container Platform into a new VPC
- Deploying OpenShift Container Platform into an existing VPC

You can also use the AWS CloudFormation templates as a starting point for your own implementation.

![Quick Start architecture for OpenShift Container Platform on AWS](https://d0.awsstatic.com/partner-network/QuickStart/datasheets/redhat-openshift-on-aws-architecture.png)

For architectural details, best practices, step-by-step instructions, and customization options, see the [deployment guide](https://s3.amazonaws.com/quickstart-reference/redhat/openshift/latest/doc/red-hat-openshift-on-the-aws-cloud.pdf).

To post feedback, submit feature ideas, or report bugs, use the **Issues** section of this GitHub repo.
If you'd like to submit code for this Quick Start, please review the [AWS Quick Start Contributor's Kit](https://aws-quickstart.github.io/).

## Usage
Using this Quick Start requires credentials for a Red Hat account that includes a subscription for Red Hat OpenShift Enterprise (note that that may require a non-personal email address registration).

The default provisioning in this Quick Start will launch 10 m4.xlarge EC2 instances (3 masters, 3 workers, 3 etcd nodes and 1 ansible configuration server).

If you have a Red Hat account and do not have easy access to the Red Hat subscription manager you can launch an RHEL instance in the AWS to determine if your account includes the necessary subscription and associated Pool ID.

Launch an RHEL instance and do the following on it to access your account

    $ sudo subscription-manager register

This will prompt you for your account name and password.

Now get a list of what is available to you with this

    $ sudo subscription-manager list --available --all

The output may include a number of sections.
If the output includes something like ```Red Hat OpenShift Enterprise``` then look for something after it called ```Pool ID: xxx```.
If you see that value keep it for use with the CloudFormation stack that you will be launching.

You also need to confirm that you have ```Entitlements Available```.
If that value is zero or does not appear at all that you may not be able to use the Quick Start.

Once you are finished with determining what you need you can unregister the host and then terminate the instance.
Unregister the instance with this

    $ sudo subscription-manager unregister
**Important**
This Quick Start will allocate from your subscription entitlements.
Before you use this ensure that you will not be taking them away from a pool that needs to be available for your company usage.

It is a good idea to go to your Red Hat account portal and ensure that your hosts and subscription entitlements have been removed after you are finished with this exercise and your instances have been terminated.

If you do not already have access to a Red Hat account then go to the following to register and get access (note that that may require a non-personal email address for registration)

[https://www.redhat.com/wapps/eval/index.html?evaluation_id=1026](https://www.redhat.com/wapps/eval/index.html?evaluation_id=1026)

Below is a write up of how to expose an application to the public internet.
Note: you can still limit access use the `ContainerAccessCIDR`

## Create a Demo Project with external access
Login into the OCP UI and Click `Create Project`:

![s3 1](https://user-images.githubusercontent.com/5912128/33403101-e0425bd2-d513-11e7-94b9-7977df42816a.jpg)

Choose `Ruby` form the Catalog:
![s3 2](https://user-images.githubusercontent.com/5912128/33403198-40527ef8-d514-11e7-9eb3-4c38a169396e.jpg)

Keep the default setting click select:
![s3 3](https://user-images.githubusercontent.com/5912128/33403230-5c4ab2b0-d514-11e7-8657-b56fee47ba2f.jpg)

Provide a value for Name and Git Repo
`Name:`  external-ruby-app
`Branch:` master
`Git Repository URL:`  Click the `Try it` to auto-fill the URL Expand the `advanced options`
![ruby1](https://user-images.githubusercontent.com/5912128/33403393-17915d6c-d515-11e7-87c9-b1b83486f03d.jpg)
Enter the ELB DNS Name in **lowercase**
_Hint: ELB DNS Name is provided in the cloud formation outputs tab under the UI link_

Specfies replicas: `3`
![ruby3](https://user-images.githubusercontent.com/5912128/33403504-8463928e-d515-11e7-911c-fa9f872df5d3.jpg)

Click `Create`
![ruby4](https://user-images.githubusercontent.com/5912128/33403558-af55348e-d515-11e7-962b-ff28f0cefad0.jpg)

`Go to the Overview `
And monitor progress
![ruby5](https://user-images.githubusercontent.com/5912128/33403590-d186be42-d515-11e7-8ad5-1669b61f9abf.jpg)

When the build is complete screen will update to show `3` pods and build at `100%`
![ruby6](https://user-images.githubusercontent.com/5912128/33403609-e93ace70-d515-11e7-8206-f82cc2feef18.jpg)

Choose the `link` provided to access the application
![ruby7](https://user-images.githubusercontent.com/5912128/33403749-6dfee0a6-d516-11e7-82ba-1abe647eaebd.jpg)
