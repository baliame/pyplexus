class Context:
    def __init__(self):
        self.aws = None
        self.configuration = {
            "aws-access-key": "",
            "aws-secret-key": "",
            "aws-region": "us-east-1",
            "aws-s3-bucket-name": "",
            "plexus-access-key": "",
            "plexus-secret-key": "",
        }

    def merge(self, kwargs, include=None, exclude=[]):
        for k, v in kwargs.items():
            key = k.replace("_", "-")
            if (include is not None and key not in include) or key in exclude:
                continue
            if v is not None:
                self.configuration[key] = v

    def config(self, k, default=None):
        key = k.replace("_", "-")
        if key in self.configuration:
            return self.configuration[key]
        return default
