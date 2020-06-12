import glob
import re
import time
import subprocess
import tarfile
import json
import logging
import os
from typing import Tuple

from ruamel import yaml

# Use this logger to forward log messages to CloudWatch Logs.
from .util import run_process, url_retreive, parse_sha256sum_file, verify_sha256sum

LOG = logging.getLogger(__name__)
log = LOG

# The minimum amount of healthy operators before the resource provider reports the cluster is healthy overall
MINIMUM_HEALTHY_OPERATORS = 25


def generate_ignition_files(openshift_install_binary, download_path, cluster_name, ssh_key, pull_secret,
                            hosted_zone_name, subnets, availability_zones, aws_access_key_id, aws_secret_access_key,
                            worker_node_size=3, certificate_arn=None, worker_instance_profile=None):
    """
    Produces a set of Ignition files and K8S/OpenShift manifests that are used to orchestrate the majority of the
    OpenShift v4 installation process.

    During bootstrap, cluster nodes (and the bootstrap server) fetch ignition files from S3. This function generates
    these ignition files and uploads up to S3

    When the installation files are generated, we temporarily assume a different AWS identity based on the passed in
    access keys. We do this because OpenShift v4 on the AWS platform *requires* a set of AWS access keys. These keys
    are stored as cluster secrets and are accessed to manage AWS resources (ex: load balancers for ingress, EC2 instances
    for MachineSets, etc.)

    :param worker_node_size: Size of initial worker cluster. Default is 3
    :param certificate_arn: The ARN to the SSL Certificate in Amazon Certificate Manager
    :param openshift_install_binary: The name of the installation binary. `openshift_install`
    :param download_path: Path to download binaries
    :param cluster_name: The name used for the Cluster
    :param ssh_key: A Public SSH key to load into the cluster for administrative access
    :param pull_secret: A valid RedHat Pull Secret JSON for fetching container images from RedHat's repository
    :param hosted_zone_name: DNS Zone name. The `cluster_name` is prepended to this to create a private DNS zone.
    :param subnets: List of all subnets IDs -- both public and private are required.
    :param availability_zones: List of availability zones. Must be at least 3 or greater.
    :param aws_access_key_id: A valid AWS Access Key ID for the Cluster to use for managing the AWS platform
    :param aws_secret_access_key: A valid AWS Secret Access Key for the Cluster to use for managing the AWS platform
    :param worker_instance_profile: [Optional] A IAM Instance Profile to attach to Worker instances

    :return Tuple(InfraName: str, KubeAdminPass: str, KubeConfig: str, AssetsDir: str):
    """
    assets_directory = download_path + cluster_name
    log.info("Creating OpenShift assets directory for {}...".format(cluster_name))
    log.debug('SSHKey: %s', ssh_key)
    log.debug('PullSecret is %s set', "" if pull_secret else "not")
    log.debug('HostedZoneName: %s', hosted_zone_name)
    log.debug('Subnets: %s', subnets)
    log.debug('Availability Zones: %s', availability_zones)
    log.debug('Cluster AWS Access Key: %s', aws_access_key_id)
    log.debug('Cluster AWS Secret Key is %s set', "" if aws_secret_access_key else "not")
    log.debug('Worker Instance Profile: %s', worker_instance_profile)

    if not os.path.exists(assets_directory):
        os.mkdir(assets_directory)
    log.info("Generating install-config file for {}...".format(cluster_name))

    # the CloudFormation logger fails if the line is empty
    for nonempty_line in [line for line in INSTALL_CONFIG_YAML.splitlines() if line]:
        log.debug(nonempty_line)

    log.info('Building Install Config YAML object')
    openshift_install_config = yaml.safe_load(INSTALL_CONFIG_YAML)
    openshift_install_config['metadata']['name'] = cluster_name
    openshift_install_config['sshKey'] = ssh_key
    openshift_install_config['pullSecret'] = pull_secret
    openshift_install_config['baseDomain'] = hosted_zone_name
    openshift_install_config['platform']['aws']['subnets'] = subnets
    openshift_install_config['platform']['aws']['region'] = os.getenv('AWS_REGION')
    openshift_install_config['controlPlane']['platform']['aws']['zones'] = availability_zones
    openshift_install_config['compute'][0]['platform']['aws']['zones'] = availability_zones
    openshift_install_config['compute'][0]['replicas'] = worker_node_size

    cluster_install_config_file = os.path.join(assets_directory, 'install-config.yaml')
    yaml.dump(openshift_install_config,
              open(cluster_install_config_file, 'w'),
              explicit_start=True, default_style='\"',
              width=4096)
    original_access_key_id = os.getenv('AWS_ACCESS_KEY_ID', '')
    original_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY', '')
    session_token = os.getenv('AWS_SESSION_TOKEN', '')
    try:
        log.debug("Using the provided AWS credentials to generate the cluster install configs. Using IAM roles is not "
                  "supported by the installer ")
        os.putenv('AWS_ACCESS_KEY_ID', aws_access_key_id)
        os.putenv('AWS_SECRET_ACCESS_KEY', aws_secret_access_key)
        os.putenv('AWS_SESSION_TOKEN', '')
        log.info("Generating manifests for {}...".format(cluster_name))
        cmd = f'{download_path}{openshift_install_binary} create manifests --dir {assets_directory}'
        run_process(cmd)
        log.info('Deleting Master Machinesets from Manifests')
        control_plane_manifests = glob.glob(
            os.path.join(assets_directory, 'openshift', '99_openshift-cluster-api_master-machines-*.yaml')
        )
        for manifest in control_plane_manifests:
            log.debug('Found Control Plane manifest to remove from installer: %s', manifest)
            os.remove(manifest)

        if certificate_arn:
            log.info('Customizing installation settings because a Certificate ARN was supplied')
            dns_manifest = os.path.join(assets_directory, 'manifests', 'cluster-dns-02-config.yml')
            with open(dns_manifest, 'r') as f:
                dns_manifest_yaml = yaml.safe_load(f)
            del dns_manifest_yaml['spec']['privateZone']
            del dns_manifest_yaml['spec']['publicZone']
            with open(dns_manifest, 'w') as f:
                yaml.dump(dns_manifest_yaml, f, explicit_start=True, default_style='\"', width=4096)
            log.info('Disabled OpenShift management of DNS records')
        else:
            log.info('No custom SSL Certificate provided. Using default behavior and OpenShift will manage DNS')

        if worker_instance_profile:
            log.info('Customizing Worker IAM Instance Profile')
            worker_manifests = glob.glob(
                os.path.join(assets_directory, 'openshift', '99_openshift-cluster-api_worker-machineset-*.yaml')
            )
            for manifest in worker_manifests:
                log.debug('Found worker manifest to modify: %s', manifest)
                with open(manifest, 'r') as f:
                    worker_machine_manifest = yaml.safe_load(f)
                log.debug('Original Worker Manifest', worker_machine_manifest)
                worker_machine_manifest['spec']['template']['spec']['providerSpec']['value']['iamInstanceProfile'][
                    'id'] = worker_instance_profile
                log.debug('New Worker Manifest', worker_machine_manifest)
                with open(manifest, 'w') as f:
                    yaml.dump(worker_machine_manifest, f, explicit_start=True, default_style='\"', width=4096)
            log.info('Finished customizing Worker Machinesets')
        else:
            log.info('No Worker Machineset customizations found. Skipping customization phase...')

        log.info("Generating ignition files for {}...".format(cluster_name))
        cmd = download_path + openshift_install_binary + " create ignition-configs --dir {}".format(assets_directory)
        run_process(cmd)
    finally:
        log.debug('Resetting AWS API access credentials')
        os.putenv('AWS_ACCESS_KEY_ID', original_access_key_id)
        os.putenv('AWS_SECRET_ACCESS_KEY', original_secret_access_key)
        os.putenv('AWS_SESSION_TOKEN', session_token)
    log.info('Collecting InfraId, KubeConfig, and KubeAdmin Password from generated installation files')
    infra_name, kubeadmin_password, kubeconfig = collect_kube_info(os.path.join(assets_directory, 'metadata.json'),
                                                                   os.path.join(assets_directory, 'auth'))
    return infra_name, kubeadmin_password, kubeconfig, assets_directory


def collect_kube_info(metadata_path, auth_path):
    """
    Accesses generated metadata and authdata files to retrieve KubeConfig, KubeAdmin Password, and Infrastructure ID

    :param metadata_path: Path to the cluster metadata json
    :param auth_path: Path to the auth directory that contains the `kubeconfig` and `kubeadmin-password` files
    :return tuple(infra_name: str, kubeadmin_password: str, kubeconfig: str):
    """
    with open(metadata_path) as f:
        metadata = json.load(f)
        infra_name = metadata['infraID']
        log.debug('Found generated cluster InfrastructureId: %s', infra_name)
    with open(os.path.join(auth_path, 'kubeadmin-password')) as f:
        kubeadmin_password = f.read().strip()
        if not kubeadmin_password:
            raise RuntimeError("No kubeadmin password found in file")
        log.debug('Found KubeAdmin password')
    with open(os.path.join(auth_path, 'kubeconfig')) as f:
        kubeconfig = f.read().strip()
        if not kubeconfig:
            raise RuntimeError("No kubeconfig found in file")

    return infra_name, kubeadmin_password, kubeconfig


def fetch_openshift_binary(openshift_client_mirror_url, openshift_install_package, openshift_install_binary,
                           download_path):
    """
    Fetch OpenShift binaries

    :param openshift_client_mirror_url: The URL to the OpenShift repository mirror for fetching command binaries
    :param openshift_install_package: The name of the `openshift_install` package
    :param openshift_install_binary: The name of the `openshfit_install` binary
    :param download_path: The path to download OpenShift binaries
    :return str: Location of binaries
    """
    sha256sum_file = 'sha256sum.txt'
    sha256sum_path = os.path.join(download_path, sha256sum_file)
    retries = 1
    url = openshift_client_mirror_url + sha256sum_file
    log.info("Downloading sha256sum file for OpenShift install client...")
    url_retreive(url, sha256sum_path)
    log.debug("Getting SHA256 hash for file %s", sha256sum_path)
    sha256sum_dict = parse_sha256sum_file(sha256sum_path)
    sha256sum = sha256sum_dict[openshift_install_package]

    # Download the openshift install binary only if it doesn't exist and retry download if the sha256sum doesn't match
    i = 0
    url = openshift_client_mirror_url + openshift_install_package
    openshift_install_package_path = os.path.join(download_path, openshift_install_package)
    while i <= retries:
        i += 1
        if os.path.exists(openshift_install_package_path):
            # Verify SHA256 hash
            if verify_sha256sum(openshift_install_package_path, sha256sum):
                log.info("OpenShift install client already exists in %s", openshift_install_package_path)
                break
        log.info("Downloading OpenShift install client...")
        url_retreive(url, openshift_install_package_path)
        if verify_sha256sum(openshift_install_package_path, sha256sum):
            log.info("Successfuly downloaded OpenShift install client...")
            break
    if not os.path.exists(os.path.join(download_path, openshift_install_binary)):
        log.info("Extracting the OpenShift install client...")
        tar = tarfile.open(openshift_install_package_path)
        tar.extractall(path=download_path)
        tar.close()
    return openshift_install_package_path


def cluster_api_available(oc: str, kubeconfig_path: str) -> bool:
    """
    Checks to see if the Cluster's API endpoint is alive

    :param oc: The OpenShift Client binary
    :param kubeconfig_path: Path to a KubeConfig file for the cluster
    :return bool: True if API available. False, otherwise
    """
    try:
        run_process(f'{oc} --config {kubeconfig_path} cluster-info')
        log.info('Cluster is available for connections')
        return True
    except (subprocess.CalledProcessError, OSError):
        log.info('Cluster is not available for connections yet')
        return False


def wait_for_operators(oc: str, kubeconfig_path: str) -> bool:
    """
    Waits for enough Cluster Operators to report back healthy. The number of reporting Operators must be greater
    than the constant `MINIMUM_HEALTHY_OPERATORS`

    :param oc: The OpenShift Client binary
    :param kubeconfig_path: Path to a KubeConfig file for the cluster
    :return bool: True if the cluster is healthy. False, otherwise
    """
    operator_re = re.compile(
        r'^(?P<operator>\S+)\s+(?P<version>\S+)\s+(?P<available>\S+)\s+(?P<progressing>\S+)\s+(?P<degraded>\S+)')
    try:
        p = run_process(f'{oc} --config {kubeconfig_path} get clusteroperators')
        operators = []
        status = 'not ready'
        for line in p.stdout.splitlines()[1:]:
            str_line = line.decode('utf-8')
            operator_match = operator_re.match(str_line)
            if operator_match is None:
                continue
            operator = operator_match.groupdict()
            operators.append(operator)
            if operator['available'] == 'False':
                log.info('[Operator Check] Waiting for operator %s to boot up', operator['operator'])
            else:
                log.info('[Operator Check] %s is ready', operator['operator'])
        if len(operators) == 0:
            log.info('[Operator Check] No operators are ready yet')
            return False
        return all([True if operator['available'] == 'True' else False for operator in operators]) and \
               len(operators) >= MINIMUM_HEALTHY_OPERATORS
    except (subprocess.CalledProcessError, OSError):
        return False


def fetch_ingress_info(oc, kubeconfig_path, session):
    """
    Fetches the Hosted Zone ID for the Ingress LoadBalancer

    :param session: Boto3 session
    :param oc: The OpenShift Client binary
    :param kubeconfig_path: Path to a KubeConfig file for the cluster
    :return bool: True if the cluster is healthy. False, otherwise
    :param cert_arn: An ACM ARN for an *.apps certificate
    :return bool:  True if post processing is successful. False, otherwise
    """
    ingress_service_re = re.compile(
        r'^(?P<name>\S+)\s+(?P<typ>\S+)\s+(?P<cluster_ip>\S+)\s+(?P<external_ip>\S+)\s+(?P<ports>\S+)')
    default_router_service = run_process(
        f'{oc} --config {kubeconfig_path} -n openshift-ingress get service router-default').stdout.splitlines()[1]
    elb = session.client('elbv2')

    router_service_match = ingress_service_re.match(default_router_service)
    if router_service_match is None:
        log.error("ERROR - Could not find default ingress router service. Can not patch service to use Certificate")
        raise RuntimeError("Could not find default ingress router service")
    router_service = router_service_match.groupdict()
    external_ip = router_service['external_ip']
    log.debug('Default ingress route external ip: %s', external_ip)

    for possible_lb in elb.describe_load_balancers(Names=external_ip.split('-')[0])['LoadBalancers']:
        log.debug('Reading LoadBalancer information %s', possible_lb)
        if possible_lb['DNSName'] == external_ip:
            return possible_lb['CanonicalHostedZoneId']
    log.error('Load Balancer zone not found')
    raise RuntimeError('Load balancer canonical zone id could not be found')


def bootstrap_post_process(oc, kubeconfig_path, certificate_arn):
    """
    Performs any post-install steps on the cluster

    :param oc: Openshift client
    :param kubeconfig_path: KubeConfig path
    :param certificate_arn: ACM Certificate ARN
    :return:
    """
    LOG.info('Starting Post-Process steps')
    if not certificate_arn:
        LOG.debug('No Certificate ARN found. No post-boot processes necessary')
        return
    patch_yaml = CERTIFICATE_PATCH_YAML.format(certificate_arn=certificate_arn)
    run_process(
        f'{oc} --config {kubeconfig_path} patch services -n openshift-ingress router-default --patch "{patch_yaml}"')

    LOG.info('Replacing default Ingress Controller')
    ingress_yaml_path = os.path.join('/tmp', 'ingress.yaml')
    with open(ingress_yaml_path, 'w') as f:
        f.write(DEFAULT_INGRESS_REPLACEMENT)
    run_process(f'{oc} --config {kubeconfig_path} replace --force --wait -f {ingress_yaml_path}')
    LOG.debug('Waiting to give LoadBalancer time to become available')
    time.sleep(30)
    LOG.info('Finished Post-Process steps')


#
# Patch YAML for changing the Ingress when a Certificate ARN is requested.
#
CERTIFICATE_PATCH_YAML = '''---
metadata:
    annotations:
        service.beta.kubernetes.io/aws-load-balancer-backend-protocol: ssl
        service.beta.kubernetes.io/aws-load-balancer-proxy-protocol: '*'
        service.beta.kubernetes.io/aws-load-balancer-ssl-cert: {certificate_arn}
        service.beta.kubernetes.io/aws-load-balancer-ssl-ports: '443'
        service.beta.kubernetes.io/aws-load-balancer-type: nlb
'''

# Used when SSL certificate integration is requested
DEFAULT_INGRESS_REPLACEMENT = '''apiVersion: v1
kind: IngressController
metadata:
    name: default
    namespace: openshift-ingress-operator
spec:
    replicas: 3
    endpointPublishingStrategy:
        type: HostNetwork
'''
#
# Template for install-config.yaml
#
INSTALL_CONFIG_YAML = '''apiVersion: v1
baseDomain: example.com 
compute:
- hyperthreading: Enabled
  name: worker
  platform:
    aws:
      zones: []
  replicas: 3
controlPlane:
  hyperthreading: Enabled
  name: master
  platform:
    aws:
      zones: []
  replicas: 3
metadata:
  creationTimestamp: null
  name: your_clustername
networking:
  clusterNetwork:
  - cidr: 10.32.0.0/16
    hostPrefix: 23
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  aws:
    region: updateme
    subnets: []

pullSecret: "{ 'UpdateMe': true }"
sshKey: |
  ssh-rsa {{ yourkey }}
'''
