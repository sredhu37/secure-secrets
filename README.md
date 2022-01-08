# SecureSecrets

## Introduction

- Allows you to store Secure (encrypted) Secrets in git.
- Creating a `SecureSecret` resource automatically creates the `Secret` resource in your cluster.

## Pre-requisites

- k8s cluster
- kubectl

## Run the following

```
# Install Customer Resource Definition
kubectl apply -f crd/secure_secrets_crd.yaml

# Install the operator
kubectl apply -f operator/secure_secret_k8s_operator.yaml

# Create a file with Test SecureSecret
cat > secure-secret-test.yaml << EOF
apiVersion: stable.redhu.com/v1
kind: SecureSecret
metadata:
  name: secure-secret-test
  namespace: default
spec:
  secretType: Opaque
  data:
  - key: myKey1
    value: myValue1
  - key: myKey2
    value: myValue2
  decryptionKeyName: key-name
EOF

# Apply the Test SecuretSecret
kubectl apply -f secure-secret-test.yaml
```

## How to contribute

Create a Pull Request with head as your branch and base as `master` branch.
