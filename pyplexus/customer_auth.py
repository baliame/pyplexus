#!/usr/bin/env python3.5

import hashlib
import json
import sys
from httphmac.v1 import V1Signer
from httphmac.request import Request
import base64

def customer_auth_sign(url_base, servkey, pl_str, context, path='/customer_key', method='POST'):
    signer = V1Signer(hashlib.sha256)
    req = Request().with_method(method).with_url("{0}/{1}".format(url_base.rstrip('/'), path.lstrip('/'))).with_header("Content-Type", "application/json").with_body(pl_str)
    if context.verbose:
        context.click.echo('*BEGIN BODY', file=sys.stderr)
        context.click.echo(pl_str, file=sys.stderr)
        context.click.echo('*END BODY', file=sys.stderr)
        context.click.echo("*BEGIN SIGNABLE", file=sys.stderr)
        context.click.echo(signer.signable(req, {}), file=sys.stderr)
        context.click.echo("*END SIGNABLE", file=sys.stderr)
    return signer.sign(req, {}, servkey)


def generate_policies(sub):
    jdata = {
        "product_policies": {
            "content_hub": {
                "permissions": [
                    "create",
                    "update",
                    "delete",
                    "reindex",
                    "retrieve",
                    "administer",
                    "search",
                    "register",
                    "recovery",
                    "create_own",
                    "update_own",
                    "delete_own",
                    "system_update",
                    "create_mapping",
                    "update_mapping",
                    "delete_mapping",
                    "retrieve_mapping"
                ]
            },
            "acquia": {
                "subscription": sub
            },
        },
    }
    return json.dumps(jdata, indent='\t')
