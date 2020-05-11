# Development notes for OpenShift4 Quick Start

# Code re-organization FYIs

- Created sub-directories to organize common, os3, and os4 templates
- More os3 resources broken up into nested child stacks
- OS4 built with more child stacks

# Differences between OS3 and OS4 Quickstarts

- Installation process is vastly different. OS3 uses a set of Ansible playbooks
  to configure the cluster. OS4 uses Ignition and a Bootstrap server to
  initiate the cluster
- OS4 is more tightly coupled with the AWS environment and is aware of AWS
  resources. During installation, OS4 will automatically set up the AWS
  resources it needs (loadbalancer, security groups)
- OS4 installation is managed by a custom resource Lambda. This Lambda uses the
  Openshift4 tools (`oc` and `openshift-install` ) to run the commands that
  normally would be manual steps in the install process
- OS4 requires a set of AWS Access keys at installation and uses these keys
  throughout the lifecycle of the cluster. This identity is used to manage
  networking resources that OpenShift needs to control in order to intgerate
  with AWS
- OS4 must use its own managed LoadBalancer for application routes (the
  services routed at `*.apps`). Because of this, there are more considerations
  for setting up the ACM SSL certificate than in OS3 (see `BYO Certificates`
      below)
- OS4 kubeadmin password is auto-generated and stored in AWS Secrets Manager
- Architecture: mostly similar except that ETCD is now located on the Control
  Plane
- Using a KeyPairName is deprecated in OS4. A public ssh key must be passed
  instead
- GlusterFS is no longer used in OS4
- Hawkular metrics is no longer used in OS4

# Feature Tasks

## BYO IAM Profiles / Roles

still **TODO** 

common pattern similar to the BYO VPC pattern:

- [ ] Add parameters for iam roles and profiles
- [ ] Set up conditionals
- [ ] Use ARNs if exist, otherwise generate

## Multiple AZ Deployment

**DONE**

## Define machine set for each AZ

**DONE** -- Autoscaling is not configured by default . up to cluster operator to set up autoscaling .

Autoscale testing was completed 05-26 . We can supply documentation on how to
set up autoscaling after cluster is set up

## Take VPC details as parameter

**DONE** --

Tested 05-28

## BYO Certificates

Allow Stack operators to pass in an ACM certificate ARN to use for the default
cluster ingress loadbalancer. OS4 installation does not natively support this and we need to code some steps into a Lambda custom resource

If user BYO certificate, do the following. Otherwise, keep default behavior (OS4 generates a classic load balancer with a self-signed certificate):
1. during installation, turn off DNS zone management
2. Wait for cluster to come up
3. Edit the Openshift router service `oc edit services -n openshift-ingress router-default` using a Lambda func / custom resource
4. Add annotations
```
service.beta.kubernetes.io/aws-load-balancer-backend-protocol: ssl
service.beta.kubernetes.io/aws-load-balancer-proxy-protocol: '*'
service.beta.kubernetes.io/aws-load-balancer-ssl-cert: <ACM_ARN>
service.beta.kubernetes.io/aws-load-balancer-ssl-ports: "443"
```
6. Wait for loadbalancer resource to be created
7. Create wildcard `*.apps.<clusterdomain>` alias record in private zone
8. Create wildcard `*.apps.<clusterdomain>` alias record in public zone

This process was tested 05-27

# TODOs

- [ ] Allow users to select number of Master nodes at install
- [ ] Allow users to select number of Worker nodes at install
- [ ] Allow users to set allowable CIDr blocks for ingress (i.e. set corporate range for ingress security group)
- [ ] AWS Service Broker install
- [ ] Custom resource provider for OPenshift4 installer
- [ ] Test some Helm Custom resources
- [ ] Known Bug: the first time we request a certificate for a new subdomain /
  clustername, the `*.apps` wildcard validation CNAME DNS record  doesn't get
  created. works every time after that
- [ ] Be more efficient with Custom Lambdas Stack -- not all the functions need to be created for OS4
