#############################################
# Variables naming convention               #
# o     => object                           #
# i     => int                              #
# s     => string                           #
# by    => bytes                            #
# l     => list                             #
# d     => dictionary                       #
#############################################

from kubernetes import client, config
from datetime import datetime
import os
import kopf
import subprocess
import base64
from cryptography.fernet import Fernet
import ssutils

config.load_incluster_config()
o_k8s_api = client.CoreV1Api()

I_KEY_GENERATION_INTERVAL = 3600      # 1 hour for now. After testing, change it to 6 months.
S_KEY_TYPE = 'fernet-key'

class Secret:
    def __init__(self, s_name, s_namespace, s_data_type, d_data, ss=None):
        self.s_name = s_name
        self.s_namespace = s_namespace
        self.s_data_type = s_data_type
        self.d_data = d_data
        self.s_decryption_key_name = None
        self.l_owner_references = None

        if ss is not None:
            self.s_decryption_key_name = ss['decryption_key_name']
            self.l_owner_references = [{
                'apiVersion': ss['api'],
                'kind': ss['kind'],
                'uid': ss['uid'],
                'name': s_name,
                'namespace': s_namespace
            }]

    def __str__(self):
        return (f"""
        Secret:
            s_name: {self.s_name}
            s_namespace: {self.s_namespace}
            s_data_type: {self.s_data_type}
            data: {self.d_data}
            s_decryption_key_name: {self.s_decryption_key_name}
            l_owner_references: {self.l_owner_references}
        """)

    def create(self):
        o_sec = client.V1Secret()

        o_sec.metadata = client.V1ObjectMeta(name = self.s_name, owner_references = self.l_owner_references)
        o_sec.type = self.s_data_type
        o_sec.data = self.d_data

        o_k8s_api.create_namespaced_secret(namespace=self.s_namespace, body=o_sec)


@kopf.on.create("securesecrets")
def create_secret(spec, body, **kwargs):
    o_secret = Secret(
        body["metadata"]["name"],
        body["metadata"]["namespace"],
        spec["secretType"],
        spec["data"],
        {
            'api': body["apiVersion"],
            'kind': body["kind"],
            'uid': body["metadata"]["uid"],
            'decryption_key_name': spec["decryptionKeyName"]
        }
    )

    print(o_secret)           # Comment this line after testing

    o_secret.create()


@kopf.timer("namespaces", interval=I_KEY_GENERATION_INTERVAL)
def create_new_key(spec, body, **kwargs):
    o_now = datetime.now()
    s_namespace = body.metadata.name

    # Ignore kube namespaces
    if s_namespace.startswith('kube-'):
        print(f"Skipping namespace: {s_namespace} as it starts with kube!")
    else:
        l_keys = list_keys(s_namespace)
        # print(f"l_keys for namespace {s_namespace}: {l_keys}")
        if len(l_keys) > 0:
            o_latest_key = l_keys[-1]
            s_latest_key_name = o_latest_key.metadata.name
            s_latest_key_datetime = s_latest_key_name.replace(f"{s_namespace}-fernet-key-", '')
            o_latest_key_datetime = datetime.strptime(s_latest_key_datetime, '%Y-%m-%d-%H-%M-%S')

            if (o_now - o_latest_key_datetime).total_seconds() < I_KEY_GENERATION_INTERVAL:
                print(f"Last key {s_latest_key_name} created: {o_now - o_latest_key_datetime} ago i.e. {(o_now - o_latest_key_datetime).total_seconds()} seconds ago. Valid key already present. Hence, not creating a new one!")
            else:
                print("All fernet keys are too old. Creating a new one.")
                create_key_and_secret(o_now, s_namespace)
        else:
            print(f"No fernet key exists for namespace: {s_namespace}. Creating a new one.")
            create_key_and_secret(o_now, s_namespace)


def list_keys(s_namespace):
    l_keys_result = o_k8s_api.list_namespaced_secret(s_namespace).items
    l_encryption_keys = list(filter(lambda o_key: o_key.metadata.name.startswith(f"{s_namespace}-{S_KEY_TYPE}-"), l_keys_result))
    l_sorted_keys = sorted(l_encryption_keys, key=lambda o_key: o_key.metadata.name)
    # print(f"Sorted keys: {l_sorted_keys}")
    return l_sorted_keys


def create_key_and_secret(o_now, s_namespace):
    s_now_hyphen = o_now.strftime('%Y-%m-%d-%H-%M-%S')

    # Create fernet key
    by_fernet_key = Fernet.generate_key()
    by_fernet_key_b64encoded = base64.b64encode(by_fernet_key)

    o_secret = Secret(
        f"{s_namespace}-{S_KEY_TYPE}-{s_now_hyphen}",
        s_namespace,
        "Opaque",
        {
            "fernet_key": by_fernet_key_b64encoded.decode()
        }
    )

    # print(f"NewKeySecret: {secret}")
    o_secret.create()
    print(f"Created new fernet key: {o_secret.s_name}")
