from ansible_collections.darkedges.forgerock.plugins.module_utils.common import ForgeRockModuleError
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.basic import to_text
from datetime import datetime
import json
from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
__metaclass__ = type

# heavily inspired by https://github.com/F5Networks/f5-ansible-bigip/blob/ee0d49f08ac0e7ecfc2cf2976d4d2d77a03e4a18/ansible_collections/f5networks/f5_bigip/plugins/httpapi/bigip.py

DOCUMENTATION = """
---
author: Nicholas Irving <nirving@darkedges.om>
httpapi: fram
short_description: HttpApi Plugin for ForgeRock Access Manager
description:
  - This HttpApi plugin provides methods to connect to ForgeRock Access Manager
    over a HTTP(S)-based api.
options:
  fram_provider:
    description:
    - The login provider used in communicating with FRAM instance when the API connection
      is first established.
    ini:
    - section: defaults
      key: fram_provider
    env:
    - name: FRAM_PROVIDER
    vars:
    - name: fram_provider
version_added: "1.0"
"""


class HttpApi(HttpApiBase):
    def __init__(self, connection):
        super(HttpApi, self).__init__(connection)
        self.connection = connection
        self.access_token = None
        self.user = None

    def set_become(self, become_context):
        """
        Elevation is not required on Fortinet devices - Skipped
        :param become_context: Unused input.
        :return: None
        """
        return None

    def login(self, username, password):
        """Call a defined login endpoint to receive an authentication token."""
        if (username is None or password is None) and self.get_access_token() is None:
            raise AnsibleConnectionFailure(
                'Username and password are required for login.')

        headers = {
            'X-OpenAM-Username': username,
            'X-OpenAM-Password': password,
            'Accept-API-Version': 'resource=2.1'
        }
        response = self.send_request(
            url='/openam/json/realms/root/authenticate', headers=headers, method='POST')
        if response['code'] == 200 and 'tokenId' in response['contents']:
            self.access_token = response['contents']['tokenId']
            if self.access_token:
                self.connection._auth = {
                    'Cookie': 'iPlanetDirectoryPro='+self.access_token
                }
            else:
                raise AnsibleConnectionFailure(
                    'Server returned invalid response during connection authentication.')
        else:
            raise AnsibleConnectionFailure('Authentication process failed, server returned: {0}'.format(
                response['contents'])
            )

    def logout(self):
        if not self.connection._auth:
            return
        token = self.connection._auth.get('X-FRAM-Auth-Token', None)
        headers = {
            'Cookie': 'iPlanetDirectoryPro='+token,
            'Accept-API-Version': 'resource=3.1,protocol=1.0'
        }
        parameters = {
            '_action': 'logout'
        }
        self.send_request('/openam/json/realms/root/sessions',
                          headers=headers, paramaters=parameters, method='POST')

    def handle_httperror(self, exc):
        if exc.code == 404:
            # 404 errors need to be handled upstream due to exists methods relying on it.
            # Other codes will be raised by underlying connection plugin.
            return exc
        if exc.code == 401:
            if self.connection._auth is not None:
                # only attempt to refresh token if we were connected before not when we get 401 on first attempt
                self.connection._auth = None
                return True
        return False

    def _concat_params(self, url, params):
        if not params or not len(params):
            return url
        url = url + '?' if '?' not in url else url
        for param_key in params:
            param_value = params[param_key]
            if url[-1] == '?':
                url += '%s=%s' % (param_key, param_value)
            else:
                url += '&%s=%s' % (param_key, param_value)
        return url

    def send_request(self, url, method=None, **kwargs):
        body = kwargs.pop('data', None)
        # allow for empty json to be passed as payload, useful for some endpoints
        data = json.dumps(body) if body or body == {} else None
        try:
            self._display_request(method, url, body)
            response, response_data = self.connection.send(
                url, data, method=method, **kwargs)
            response_value = self._get_response_value(response_data)
            return dict(
                code=response.getcode(),
                contents=self._response_to_json(response_value),
                headers=response.getheaders()
            )
        except HTTPError as e:
            return dict(code=e.code, contents=json.loads(e.read()))

    def _display_request(self, method, url, data=None):
        if data:
            self._display_message(
                'FRAM API Call: {0} to {1} with data {2}'.format(
                    method, url, data)
            )
        else:
            self._display_message(
                'FRAM API Call: {0} to {1}'.format(method, url)
            )

    def _display_message(self, msg):
        self.connection._log_messages(msg)

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise ForgeRockModuleError(
                'Invalid JSON response: %s' % response_text)
