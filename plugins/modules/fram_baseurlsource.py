from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ..module_utils.common import ForgeRockModuleError
from ansible.module_utils.six import string_types
from ..module_utils.framclient import (
    FRAMClient
)
from ..module_utils.common import (
    ForgeRockModuleError, AnsibleForgeRockParameters,
)

# heavily inspired by https://github.com/F5Networks/f5-ansible-bigip/blob/ee0d49f08ac0e7ecfc2cf2976d4d2d77a03e4a18/ansible_collections/f5networks/f5_bigip/plugins/modules/bigiq_regkey_pool.py

DOCUMENTATION = r'''
---
module: fram_basesource

short_description: This helps automate Configuring the Base URL Source Service

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "0.0.1"

description: This helps automate [Configuring the Base URL Source Service](https://backstage.forgerock.com/docs/am/6.5/oidc1-guide/index.html#configure-base-url-source)

options:
    context_path:
        description: Specifies the context path for the base URL. If provided, the base URL includes the deployment context path appended to the calculated URL. For example, `/openam`.
        required: false
        type: str
    fixed_value :
        description:
           If Fixed value is selected as the Base URL source, enter the base URL in the Fixed value base URL field.
        required: false
        type: str
    source:
        description:
            - Extension class. `EXTENSION_CLASS`
              Specifies that the extension class returns a base URL from a provided `HttpServletRequest`. In the Extension class name field, enter org.forgerock.openam.services.baseurl.BaseURLProvider.
            - Fixed value. `FIXED_VALUE`
              Specifies that the base URL is retrieved from a specific base URL value. In the Fixed value base URL field, enter the base URL value.
            - Forwarded header. `FORWARDED_HEADER`
              Specifies that the base URL is retrieved from a forwarded header field in the HTTP request. The Forwarded HTTP header field is standardized and specified in [RFC7239](https://tools.ietf.org/html/rfc7239).
            - Host/protocol from incoming request. `REQUEST_VALUES`
              Specifies that the hostname, server name, and port are retrieved from the incoming HTTP request.
            - X-Forwarded-* headers. `X_FORWARDED_HEADERS`
		Specifies that the base URL is retrieved from non-standard header fields, such as `X-Forwarded-For`, `X-Forwarded-By`, and `X-Forwarded-Proto`.
        required: false
        type: str
    extension_class_name:
        description:
            If Extension class is selected as the Base URL source, enter `org.forgerock.openam.services.baseurl.BaseURLProvider` in the Extension class name field.
        required: false
        type: str        
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - darkedges.forgerock.fram_fragment

author:
    - Nicholas Irving (@darkedges)
'''

EXAMPLES = r'''
# Pass in a message
- name: Test with a message
  darkedges.forgerock.fram_baseurlsource:
    source: "FIXED_VALUE"
    fixed_value: "https://fram.example.com"
    context_path: "/openam"
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
message:
    description: Result
    type: str
    returned: always
    sample: 'ok'
'''


class Parameters(AnsibleForgeRockParameters):
    api_map = {
        'fixedValue': 'fixed_value',
        'contextPath': 'context_path',
        'extensionClassName': 'extension_class_name',
        'source': 'source'
    }
    api_attributes = [
        'fixedValue',
        'contextPath',
        'extensionClassName',
        'source',
    ]

    returnables = [
        'source',
        'fixed_value',
        'context_path',
        'extension_class_name'
    ]

    updatables = [
        'source',
        'fixed_value',
        'context_path',
        'extension_class_name'
    ]

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result


class ModuleParameters(Parameters):
    pass


class ApiParameters(Parameters):
    pass


class Changes(Parameters):
    pass


class ReportableChanges(Changes):
    pass


class UsableChanges(Changes):
    pass


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.connection = kwargs.get('connection', None)
        self.client = FRAMClient(module=self.module, client=self.connection)
        self.want = ModuleParameters(
            client=self.client, params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = Changes(params=changed)
            return True
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def exec_module(self):
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()
        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        return result

    def _announce_deprecations(self, result):
        warnings = result.pop('__warnings', [])
        for warning in warnings:
            self.module.deprecate(
                msg=warning['msg'],
                version=warning['version']
            )

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def exists(self):
        uri = "/openam/json/realms/{0}/realm-config/services/baseurl".format(
            'root')
        code, self.have = self.read_current_from_device()

        if code == 404:
            return False

        if code not in [200, 201, 202]:
            raise ForgeRockModuleError(response['contents'])

        return True

    def update(self):
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise ForgeRockModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def create_on_device(self):
        params = self.changes.api_params()

        headers = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'SwaggerUI'
        }

        uri = "/openam/json/realms/{0}/realm-config/services/baseurl".format(
            'root')

        response = self.client.put(uri, data=params, headers=headers)

        if response['code'] not in [201]:
            raise ForgeRockModuleError(response['contents'])

        return True

    def update_on_device(self):
        params = self.changes.api_params()

        headers = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'SwaggerUI'
        }

        uri = "/openam/json/realms/{0}/realm-config/services/baseurl".format(
            'root')
        response = self.client.put(uri, data=params, headers=headers)

        if response['code'] not in [200]:
            raise ForgeRockModuleError(response['contents'])

        return True

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def remove_from_device(self):
        uri = "/openam/json/realms/{0}/realm-config/services/baseurl".format(
            'root')
        headers = {
            'X-Requested-With': 'SwaggerUI',
            'Accept-API-Version': 'resource=1.0,protocol=1.0'
        }
        response = self.client.delete(uri, headers=headers)

        if response['code'] in [200, 201, 202]:
            return True
        raise ForgeRockModuleError(response['contents'])

    def read_current_from_device(self):
        uri = "/openam/json/realms/{0}/realm-config/services/baseurl".format(
            'root')
        response = self.client.get(uri)

        if response['code'] not in [200, 201, 202]:
            raise ForgeRockModuleError(response['contents'])

        return response['code'], ApiParameters(params=response['contents'])


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            context_path=dict(type='str', required=False, default="/openam"),
            fixed_value=dict(type='str', required=False,
                             default="http://localhost:8080"),
            source=dict(type='str', required=False, default="FIXED_VALUE"),
            extension_class_name=dict(
                type='str', required=False),
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
        )
        self.argument_spec = {}
        self.argument_spec.update(argument_spec)
        self.required_if = [
        ]


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(
            module=module, connection=Connection(module._socket_path))
        results = mm.exec_module()
        module.exit_json(**results)
    except ForgeRockModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
