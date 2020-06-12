"""
Set of utility functions to use with this Resource Provider
"""
import logging
from typing import Optional, Mapping

import boto3
import os
import sys
import urllib
import hashlib
import subprocess

from botocore.exceptions import ClientError

# Use this logger to forward log messages to CloudWatch Logs.
from cloudformation_cli_python_lib import SessionProxy, OperationStatus

from .models import ResourceModel
from .openshift import fetch_ingress_info, fetch_openshift_binary

LOG = logging.getLogger(__name__)
log = LOG  # alias


def fetch_resource(model: Optional[ResourceModel], session: Optional[SessionProxy]) -> Mapping:
    """
    Fetches resource information from AWS and adds them to our model.

    We specifically grab the Infrastructure ID from Parameter store and any Kubernetes information from Secrets Manager

    :param model: Resource model
    :param session: Boto SessionProxy
    :return Mapping: A Mapping of values that can be used as **kwargs to a ProgressEvent or used for something else
    """
    secrets = session.client('secretsmanager')
    ssm = session.client('ssm')
    LOG.info('Retrieving Cluster information from AWS Parameter Store and Secrets Manager')
    try:
        LOG.debug('Fetching Infrastructure ID')
        model.InfrastructureId = ssm.get_parameter(
            Name=f'/OpenShift/{model.ClusterName}/InfrastructureId'
        )['Parameter']['Value']
        LOG.debug('Fetching KubeConfig')
        model.KubeConfigArn = model.KubeConfig = \
            secrets.describe_secret(SecretId=f'{model.InfrastructureId}-kubeconfig')['ARN']

    except ssm.exceptions.ParameterNotFound:
        err_msg = f"ERROR - Parameter at /OpenShift/{model.ClusterName}/InfrastructureId not found"
        LOG.error(err_msg)
        return {
            'status': OperationStatus.FAILED,
            'message': err_msg,
            'resourceModel': model
        }
    except secrets.exceptions.ResourceNotFoundException as e:
        err_msg = f'ERROR - Required Secret values for Kubernetes connections could not be found: {e}'
        LOG.error(err_msg)
        return {
            'status': OperationStatus.FAILED,
            'message': err_msg,
            'resourceModel': model
        }
    # Bootstrap Action does not need KubeAdminPassword
    try:
        LOG.debug('Fetching KubeAdminPassword')
        model.KubeAdminPasswordArn = secrets.describe_secret(SecretId=f'{model.InfrastructureId}-kubeadmin')['ARN']
    except secrets.exceptions.ResourceNotFoundException as e:
        if model.Action == 'GENERATE_IGNITION':
            err_msg = f'ERROR - Required Secret values for Kubernetes admin password could not be found: {e}',
            LOG.error(err_msg)
            return {
                'status': OperationStatus.FAILED,
                'message': err_msg,
                'resourceModel': model
            }
        LOG.warning('WARNING - KubeAdminPassword not required for BOOTSTRAP action. Continuing...')

    log.info('Reading Ingress information from Cluster')
    openshift_client_binary = model.OpenShiftClientBinary
    openshift_version = model.OpenShiftVersion
    openshift_client_mirror_url = f'{model.OpenShiftMirrorURL}{openshift_version}/'
    openshift_client_package = f'openshift-client-linux-{openshift_version}.tar.gz'
    fetch_openshift_binary(openshift_client_mirror_url, openshift_client_package, openshift_client_binary, '/tmp/')
    oc_bin = f'/tmp/{openshift_client_binary}'

    kubeconfig_path = write_kubeconfig(session, model.KubeConfigArn)
    model.IngressZoneId, model.IngressDNS = fetch_ingress_info(oc_bin, kubeconfig_path, session)
    return {'status': OperationStatus.SUCCESS, 'resourceModel': model}


def write_kubeconfig(session, kubeconfig_id, parent_dir='/tmp/'):
    """
    Fetches kubeconfig from secrets manager and writes to file

    :param session:  Boto3 session
    :param parent_dir: where to install kubeconfig file
    :return str: Path to kubeconfig
    """
    LOG.debug('[CREATE] Fetching KubeConfig from Secrets Manager at %s', kubeconfig_id)
    secrets = session.client('secretsmanager')
    kubeconfig_path = os.path.join('/tmp/', 'kubeconfig')
    kubeconfig = secrets.get_secret_value(SecretId=kubeconfig_id)
    with open(kubeconfig_path, 'w') as f:
        f.write(kubeconfig['SecretString'])
    return kubeconfig_path


def verify_sha256sum(filename, sha256sum):
    """
    Takes a filename and runs a SHA256 checksum to validate

    :param filename: The filename to verify
    :param sha256sum: The SHA256 checksum to check against
    :return bool: True if checksum is correct. False, otherwise
    """
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as file:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)
    if sha256_hash.hexdigest() == sha256sum:
        return True
    else:
        log.info("File {} SHA256 hash is {}".format(filename, sha256_hash.hexdigest()))
        log.info("Expecting {}".format(sha256sum))
        return False


def url_retreive(url, download_path):
    """
    Fetch a URL helper func

    :param url: The URL to fetch
    :param download_path: Path to download the URL body
    :return None:
    """
    log.debug("Downloading from URL: {} to {}".format(url, download_path))
    try:
        urllib.request.urlretrieve(url, download_path)
    except urllib.error.HTTPError as e:
        log.error("Failed to download {} to {}".format(url, download_path))
        log.error("Error code: {}".format(e))
    except urllib.error.URLError as e:
        log.error("Reason: {}".format(e))
        sys.exit(1)


def parse_sha256sum_file(filename):
    """
    Takes a SHA256 checksum file and returns the values as a dict

    :param filename: The file with SHA256 checksums
    :return Mapping: Check sums from file
    """
    with open(filename, 'r') as file:
        string = file.read()
    string = string.rstrip()
    # Parse file into a dictionary, the file format is
    # shasum  filename\nshasum1  filename1\n...
    tmp_dict = dict(item.split("  ") for item in string.split("\n"))
    # Swap keys and values
    sha256sums = dict((v, k) for k, v in tmp_dict.items())
    return sha256sums


def run_process(cmd):
    """
    Run a command as a sub-process
    :param cmd: Command to run
    :return: The completed sub-process object
    """
    log.debug("running cmd: %s", cmd)
    try:
        proc = subprocess.run([cmd], capture_output=True, shell=True)
        proc.check_returncode()
        log.debug(f'Return code: {proc.returncode}')
        log.debug(f'Stdout: {proc.stdout}')
        log.debug(f'Stderr: {proc.stderr}')
        return proc
    except subprocess.CalledProcessError as e:
        log.error("Error Detected on cmd {} with error {}".format(e.cmd, e.stderr))
        log.error(e.cmd)
        log.error(e.stderr)
        log.error(e.stdout)
        raise
    except OSError as e:
        log.error("Error Detected on cmd {} with error {}".format(e.cmd, e.stderr))
        log.error("OSError: {}".format(e.errno))
        log.error(e.strerror)
        log.error(e.filename)
        raise


def upload_file_to_s3(s3_path, local_path, s3_bucket, session: Optional[SessionProxy]):
    """
    Upload file to S3 bucket helper func

    :param session: Boto SessionProxy
    :param s3_path: Path in S3 to upload the file
    :param local_path: Local path to file
    :param s3_bucket: Name of the S3 bucket
    :return:
    """
    client = session.client('s3')
    log.info("Uploading {} to s3 bucket {}...".format(local_path, os.path.join(s3_bucket, s3_path)))
    try:
        log.debug('Checking if object exists at location %s', s3_path)
        client.head_object(Bucket=s3_bucket, Key=s3_path)
    except ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = e.response['Error']['Code']
        if error_code == '404':
            log.debug('No object found. Continuing to upload')
            return client.upload_file(local_path, s3_bucket, s3_path)
        else:
            log.error('S3 Client Error Code: %s', error_code)
            raise e
    else:
        log.error("File found on S3! %s", s3_path)
        raise RuntimeError("An object already exists in S3 at that location. Please clear out the Ignition location")


def upload_ignition_files_to_s3(local_folder, s3_bucket, session: SessionProxy):
    """
    Push Ignition files up to S3

    :param session: Boto SessionProxy
    :param local_folder: The folder to upload
    :param s3_bucket: Name of the S3 Bucket
    :return None:
    """
    files_to_upload = ['auth/kubeconfig', 'auth/kubeadmin-password', 'master.ign', 'worker.ign', 'bootstrap.ign']
    for file in files_to_upload:
        s3_path = os.path.join(os.path.basename(local_folder), file)
        local_path = os.path.join(local_folder, file)
        upload_file_to_s3(s3_path, local_path, s3_bucket, session)


def delete_contents_s3(s3_bucket, session: SessionProxy, filter: Optional[Mapping] = None):
    """
    Clear out an S3 bucket. Handy for cleaning up if the CF Resource is deleted. Default is to delete all objects from
    the bucket.

    Optionally, pass a filter that is passed as **kwargs to the boto3.Bucket.objects.filter(**kwargs) call
    :param session: Boto SessionProxy
    :param filter: A Mapping of valid Filters for the AWS S3 API action `GetObjects`
    :param s3_bucket: Name of the S3 bucket to delete objects from
    :return None:
    """
    s3 = session.resource('s3')
    bucket = s3.Bucket(s3_bucket)
    try:
        if filter is None:
            log.debug("Deleting bucket {}...".format(s3_bucket))
            bucket.objects.all().delete()
        else:
            bucket.objects.filter(**filter).delete()
    except ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        error_code = e.response['Error']['Code']
        if error_code == "NoSuchBucket":
            log.debug("{} does not exist, skipping...".format(s3_bucket))
            return
        else:
            log.error("Failed to delete bucket, unhandled exception {}".format(e))
            raise e
    except Exception as e:
        log.error("Failed to delete bucket, unhandled exception {}".format(e))
        raise e


def get_from_s3(s3_bucket, source, destination):
    """
    Fetch an object from S3 helper func
    :param s3_bucket: Name of the S3 Bucket
    :param source: Key in S3 to fetch
    :param destination: Local location to write the object to
    :return None:
    """
    client = boto3.client('s3')
    if check_file_s3(s3_bucket, key=source):
        client.download_file(s3_bucket, source, destination)


def add_file_to_s3(s3_bucket, body, key, content_type, acl):
    """
    Push a blob to S3 helper func

    :param s3_bucket: Name of the S3 Bucket
    :param body: Content of the object to create
    :param key: Key for the new object in S3
    :param content_type: Object content-type
    :param acl: Any S3 ACL to apply
    :return None:
    """
    client = boto3.client('s3')
    client.put_object(Body=body, Bucket=s3_bucket, Key=key,
                      ContentType=content_type, ACL=acl)


def delete_s3_file(s3_bucket, file_name, session: SessionProxy):
    """
    Delete an individual file object from S3

    :param session: Boto SessionProxy
    :param s3_bucket: Name of the S3 bucket
    :param file_name: Name of object to delete in S3
    :return:
    """
    client = session.client('s3')
    client.delete_object(Bucket=s3_bucket, Key=file_name)


def check_file_s3(s3_bucket, key, session: SessionProxy):
    """
    Check if key exists in S3 bucket
    :param session: Boto SessionProxy
    :param s3_bucket: Name of the S3 bucket to check
    :param key: Object key
    :return:
    """
    client = session.client('s3')
    try:
        client.head_object(Bucket=s3_bucket, Key=key)
        log.debug("File at location {} found".format(key))
        return True
    except Exception as e:
        log.debug("File not found at {} and key {}".format(s3_bucket, key))
        return False
