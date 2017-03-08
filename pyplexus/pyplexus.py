from .aws import AWS
from .context import Context
from .customer_auth import customer_auth_sign, generate_policies
import click
import json
import os
from httphmac.request import Request
from httphmac.v2 import V2Signer as Signer
import requests
import hashlib
import ntpath
import uuid
import base64
import sys
import time

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

context = Context()


def leaf(fname):
    head, tail = ntpath.split(fname)
    return tail or ntpath.basename(head)


@click.group()
@click.option("--aws-access-key", type=str, envvar='PLEXUS_AWS_ACCESS_KEY', help='AWS access key to be used for AWS operations.')
@click.option("--aws-secret-key", type=str, envvar='PLEXUS_AWS_SECRET_KEY', help='AWS secret key to be used for AWS operations.')
@click.option("--aws-region", type=str, envvar='PLEXUS_AWS_REGION', default='us-east-1', help='AWS region to be used for AWS operations.')
@click.option("--aws-s3-bucket-name", type=str, envvar="PLEXUS_AWS_S3_BUCKET_NAME", default='plexus-cli.do-not-delete', help='S3 bucket to use for curl data-resource operations.')
@click.option("-v", "--verbose", is_flag=True)
def cli(**kwargs):
    try:
        with open('%s/.config/Acquia/plexus.json' % os.getenv('HOME'), 'r') as f:
            contents = f.read()
        data = json.loads(contents)
        context.merge(data)
    except FileNotFoundError:
        pass
    context.merge(kwargs, exclude=["verbose"])
    context.verbose = kwargs["verbose"]
    context.aws = AWS(context.config("aws-access-key", None), context.config("aws-secret-key", None), context.config("aws-region", "us-east-1"), resources=['s3'], clients=['cloudformation'])
    context.click = click


@cli.command()
@click.argument('stack_name')
@click.argument('subscription')
@click.option('--client-id', type=str, envvar='PLEXUS_CLIENT_ID', help='Sets the client ID of the flood create requests. Must be a valid client ID.')
def flood(**kwargs):
    sname = kwargs.get("stack_name", None)
    if sname is None:
        raise ValueError("Stack name must be provided.")
    if kwargs.get("subscription", None) is None:
        raise ValueError("Subscription must be provided.")
    dir(context.aws.cloudformation)
    stack = context.aws.cloudformation.describe_stack_resources(StackName=sname)
    q = None
    for resource in stack['StackResources']:
        if resource['LogicalResourceId'] == 'QueueApp':
            q = resource['PhysicalResourceId']
    if q is None:
        raise ValueError('No matching stacks or queue found.')
#   scount = len(stack['Stacks'])
#   if scount != 1:
#       if scount == 0:
#           raise ValueError('No matching stacks found.')
#       else:
#           raise ValueError('Stack name ambiguous, matched {0} stacks.'.format(scount))


@cli.command()
@click.argument('stack_name')
@click.argument('subscription')
@click.option('--ca-access-key', type=str, envvar='CUSTOMER_AUTH_ACCESS_KEY', help='Overrides the stack access key. Must be provided if ca-secret-key is provided.')
@click.option('--ca-secret-key',  type=str, envvar='CUSTOMER_AUTH_SECRET_KEY', help='Overrides the stack secret key. Must be provided if ca-access-key is provided.')
def keygen(**kwargs):
    cak = kwargs.get("ca_access_key")
    cas = kwargs.get("ca_secret_key")
    auth = {
        "AuthAccessKey": None,
        "AuthServiceKey": None,
        "AuthServiceUrl": None,
    }
    if cak is not None or cas is not None:
        if cak is None or cas is None:
            raise ArgumentError('ca-access-key and ca-secret-key must be both provided or neither should be provided.')
        auth["AuthAccessKey"] = cak
        auth["AuthServiceKey"] = cas
    sname = kwargs.get("stack_name", None)
    if sname is None:
        raise ValueError("Stack name must be provided.")
    if kwargs.get("subscription", None) is None:
        raise ValueError("Subscription must be provided.")
    stack = context.aws.cloudformation.describe_stacks(StackName=sname)
    scount = len(stack['Stacks'])
    if scount != 1:
        if scount == 0:
            raise ValueError('No matching stacks found.')
        else:
            raise ValueError('Stack name ambiguous, matched {0} stacks.'.format(scount))
    for p in stack['Stacks'][0]['Parameters']:
        if p['ParameterKey'] in auth and auth[p['ParameterKey']] is None:
            auth[p['ParameterKey']] = p['ParameterValue']
    payload = generate_policies(kwargs.get("subscription"))
    sig = customer_auth_sign(auth["AuthServiceUrl"], auth["AuthServiceKey"], payload, context)
    if context.verbose:
        context.click.echo('*SIGNATURE: {0}'.format(sig), file=sys.stderr)
    r = requests.post("{0}/customer_key".format(auth["AuthServiceUrl"]), data=payload, headers={
        "Authorization": "CustomerAuthTest {0}:{1}".format(auth["AuthAccessKey"], sig),
        "X-Acquia-Timestamp": int(time.time()),
        "Content-Type": "application/json",
    }, verify=False)
    print(r.json())


@cli.command()
@click.argument('url')
@click.option("--plexus-access-key", type=str, envvar='PLEXUS_ACCESS_KEY', help='The customer auth access key to use with plexus curl operations.')
@click.option("--plexus-secret-key", type=str, envvar='PLEXUS_SECRET_KEY', help='The customer auth secret key to use with plexus curl operations.')
@click.option("-d", "--data", type=str, help='Provides the request body as inline text. Mutually exclusive with other body options. Automatically converts request method to POST if no method is provided.')
@click.option("--data-file", type=str, help='Provides the request body from the contents of the file at this path. Mutually exclusive with other body options. Automatically converts request method to POST if no method is provided.')
@click.option("--data-resource", type=str, help='Provides a resource, which is uploaded to an S3 bucket. The request body is automatically generated for the URL of the file. Mutually exclusive with other body options. Automatically converts request method to POST if no method is provided.')
@click.option("-X", "--request", type=str, help='Sets the request method. Defaults to GET if no data is provided, or POST if data is provided.')
@click.option("--client-id", type=str, envvar='PLEXUS_CLIENT_ID', help='Sets the value of the X-Acquia-Plexus-Client-Id header. Required for most endpoints.')
def curl(**kwargs):
    context.merge(kwargs, include=['plexus-access-key', 'plexus-secret-key'])

    url = kwargs.get("url", None)
    if url is None or url == "":
        raise ValueError('Destination URL must be provided.')

    bodycount = 0
    if kwargs.get("data") is not None:
        bodycount += 1
    if kwargs.get("data_file") is not None:
        bodycount += 1
    if kwargs.get("data_resource") is not None:
        bodycount += 1
    if bodycount > 1:
        raise KeyError('Cannot specify more than one type of data.')

    method = kwargs.get("request")
    if method is None:
        if kwargs.get("data") is not None or kwargs.get("data_file") is not None or kwargs.get("data_resource") is not None:
            method = "POST"
        else:
            method = "GET"
    else:
        method = method.upper()

    request = Request().with_url(url).with_method(method)

    if bodycount > 0:
        if kwargs.get("data") is not None:
            request.with_json_body(kwargs.get("data"))
        elif kwargs.get("data_file") is not None:
            with open(kwargs.get("data_file")) as f:
                request.with_json_body(f.read())
        elif kwargs.get("data_resource") is not None:
            fname = kwargs.get("data_resource")
            with open(fname) as f:
                jd = f.read()
            jdict = json.loads(jd)
            request.with_json_body({
                'data': jdict
            })

    if kwargs.get("client_id") is not None:
        request.with_header("X-Acquia-Plexus-Client-Id", kwargs.get("client_id"))

    request.with_time()

    auth = {
        "id": context.config("plexus-access-key"),
        "nonce": uuid.uuid4(),
        "realm": "Plexus",
        "version": "2.0",
    }

    signer = Signer(hashlib.sha256)

    bodyhash = None
    if request.body is not None and request.body != b'':
        content_hash = request.get_header("x-authorization-content-sha256")
        if content_hash == '':
            raise KeyError("X-Authorization-Content-SHA256 is required for requests with a request body.")
        sha256 = hashlib.sha256()
        sha256.update(request.body)
        bodyhash = base64.b64encode(sha256.digest()).decode('utf-8')
        if content_hash != bodyhash:
            raise ValueError("X-Authorization-Content-SHA256 must match the SHA-256 hash of the request body.")

    if context.verbose:
        click.echo("*BEGIN SIGNABLE", file=sys.stderr)
        click.echo(signer.signable(request, auth, bodyhash), file=sys.stderr)
        click.echo("*END SIGNABLE", file=sys.stderr)

    signer.sign_direct(request, auth, context.config("plexus-secret-key"))

    if context.verbose:
        click.echo("*Request headers: %s" % (request.header), file=sys.stderr)

    resp = request.do()
    print(resp.json())
