import json

# heavily inspired by https://github.com/F5Networks/f5-ansible-bigip/blob/ee0d49f08ac0e7ecfc2cf2976d4d2d77a03e4a18/ansible_collections/f5networks/f5_bigip/plugins/module_utils/client.py


class FRAMClient():
    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.module = kwargs.get('module', None)
        self.plugin = kwargs.get('client', None)
        self.transact = None

    def put(self, url, data=None, **kwargs):
        return self.plugin.send_request(url, method='PUT', data=data, **kwargs)

    def get(self, url, **kwargs):
        return self.plugin.send_request(url, method='GET', **kwargs)

    def delete(self, url, **kwargs):
        return self.plugin.send_request(url, method='DELETE', **kwargs)
