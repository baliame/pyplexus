#!/usr/bin/env python3.5

import hashlib
import json
from httphmac.v1 import V1Signer
from httphmac.request import Request


def customer_auth_sign(url_base, servkey, pl_str):
    signer = V1Signer(hashlib.sha256)
    req = Request().with_method("POST").with_url("{0}/customer_key".format(url_base)).with_header("Content-Type", "application/json").with_body(pl_str)
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
                    "delete_own"
                ]
            },
            "acquia": {
                "subscription": sub
            },
        },
    }
    return json.dumps(jdata)
