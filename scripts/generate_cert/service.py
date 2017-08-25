# built for AWS Lambda
# author: # Tony Vattathil avattathil@gmail.com
# This program create x509 Private Key,Public Key and Certificate Chain
#

from __future__ import print_function
import os
import json
import cfnresponse
import datetime
import cryptography 
from botocore.vendored import requests
from cfnresponse import send
from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

'''
Generate private_Key Publicr_ Key Certificate_Chain
returns: public_key_certificate, private_key, certificate_chain
'''

def generate_selfsigned_cert(common_name, alternative_names, key_size):
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=key_size,
                                   backend=default_backend()
                                   )
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    alt_names = x509.SubjectAlternativeName([
        x509.DNSName(alternative_names),
    ])
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=10 * 365))
            .add_extension(basic_contraints, False)
            .add_extension(alt_names, False)
            .sign(key, hashes.SHA256(), default_backend())
    )
    public = cert.public_bytes(encoding=serialization.Encoding.PEM)
    private = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_certificate = public.decode('utf-8')
    private_key = private.decode('utf-8')
    certificate_chain = ''.join([public_key_certificate, private_key])

    return public_key_certificate, private_key, certificate_chain


'''
input: cloudformation events, context
returns: public_key_certificate, private_key, certificate_chain via response_data
'''

def handler(event, context):
    response_data ={}
    if event['RequestType'] == 'Delete':
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
        return cfnresponse.SUCCESS

    try:
        common_name = unicode(os.environ['common_name'])
        alternative_name = unicode(os.environ['alternative_name'])
        response_data['PRIVATE_KEY'], response_data['PUBLIC_KEY'], response_data['CERTIFICATE_CHAIN'] = generate_selfsigned_cert(common_name, alternative_name, 1024)
        send(event, context, cfnresponse.SUCCESS, "created certs",  response_data)
    except Exception as err:
        print (err)
        send(event, context, cfnresponse.FAILED, err, {})
        return cfnresponse.FAILED
    return 'COMPLETED'



