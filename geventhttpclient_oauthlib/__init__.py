# coding=utf-8

from geventhttpclient.client import HTTPClient
from oauthlib.oauth1.rfc5849 import (
    Client, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER)


class OAUTH1Request(HTTPClient):
    def __init__(self, *args, **kwargs):
        super(OAUTH1Request, self).__init__(*args, **kwargs)
        self.client = None

    def set_oauth_params(
            self, client_key,
            client_secret=None,
            resource_owner_key=None,
            resource_owner_secret=None,
            callback_uri=None,
            signature_method=SIGNATURE_HMAC,
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            rsa_key=None, verifier=None, realm=None,
            convert_to_unicode=False, encoding='utf-8'):
        self.client = Client(
            client_key, client_secret, resource_owner_key,
            resource_owner_secret, callback_uri, signature_method,
            signature_type, rsa_key, verifier)

    def _build_request(self, method, request_uri, body=u"", headers={}):
        # oauthlib expects None instead of empty string
        if not body:
            body = None
        method = unicode(method)
        request_uri = unicode(request_uri)
        uri, headers, body = self.client.sign(
            uri=request_uri,
            http_method=method,
            body=body,
            headers=headers)
        return super(OAUTH1Request, self)._build_request(
            method, uri, body="", headers=headers)
