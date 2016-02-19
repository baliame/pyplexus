import boto3
import boto3.session


class AWS:
    def __init__(self, access=None, secret=None, region='us-east-1', resources=[], clients=[]):
        self.region = region

        if access is None or secret is None:
            self.sessid = "__ROLE__"
            self.session = boto3.session.Session(region_name=self.region)
        else:
            self.sessid = access
            self.session = boto3.session.Session(aws_access_key_id=access, aws_secret_access_key=secret, region_name=self.region)

        for res in resources:
            setattr(self, res, self.session.resource(res))

        for cli in clients:
            setattr(self, cli, self.session.client(cli))

    def session_key(self):
        return "%s--%s" % (self.sessid, self.region)

    def session(self):
        return self.session
