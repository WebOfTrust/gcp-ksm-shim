from google.cloud import kms
from keri.core import coring, eventing

from gcp_ksm_shim.core import keeping

project_id = "advance-copilot-319717"
location_id = "us-west1"
key_ring_id = "signify-key-ring"
key_id = "signify-key"
version_id = "1"
member = "serviceAccount:signifykeygeneration@advance-copilot-319717.iam.gserviceaccount.com"

next_key_id = "inception_next_key"
signing_key_id = "inception_signing_key"


def test_module():
    # stem = randomNonce()
    stem = "ABO4qF9g9L-e1QzvMXgY-58elMh8L-63ZBnNXhxScO81"
    mod = keeping.GcpKsmShim(project_id, location_id, key_ring_id, pidx=0, transferable=True, stem=stem)
    keys, ndigs = mod.incept()
    assert len(keys) == 1
    assert keys[0].startswith("1AAB")
    assert len(keys[0]) == 48

    assert len(ndigs) == 1
    assert ndigs[0].startswith("E")
    assert len(ndigs[0]) == 44

    params = mod.params()
    assert params == {'dcode': 'E',
                      'icount': 1,
                      'kidx': 0,
                      'ncount': 1,
                      'pidx': 0,
                      'stem': 'ABO4qF9g9L-e1QzvMXgY-58elMh8L-63ZBnNXhxScO81',
                      'tier': 'low',
                      'transferable': True}

    serder = eventing.incept(keys=keys,
                             isith='1',
                             nsith='1',
                             ndigs=ndigs,
                             code=coring.MtrDex.Blake3_256,
                             wits=[],
                             toad='0')

    print()
    sigs = mod.sign(ser=serder.raw, indices=[0])
    assert len(sigs) == 1
    assert sigs[0].startswith('C')

    cigs = mod.sign(ser=serder.raw, indexed=False)
    assert len(cigs) == 1
    assert cigs[0].startswith('0C')

    sigers = [coring.Siger(qb64=sig) for sig in sigs]
    msg = eventing.messagize(serder=serder, sigers=sigers)
    print(msg)


def test_list_keys():
    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the resource name.
    # resource_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

    # The resource name could also be a key ring.
    resource_name = client.key_ring_path(project_id, location_id, key_ring_id)
    print(resource_name)
    # Get the current policy.
    keys = client.list_crypto_keys(parent=resource_name)
    for key in keys:
        print(key.name)


def test_create_keyring():
    client = kms.KeyManagementServiceClient()
    location_name = f'projects/{project_id}/locations/{location_id}'

    key_ring = {}

    # Call the API.
    created_key_ring = client.create_key_ring(
        request={'parent': location_name, 'key_ring_id': key_ring_id, 'key_ring': key_ring})
    print('Created key ring: {}'.format(created_key_ring.name))
    return created_key_ring


def test_create_key():
    client = kms.KeyManagementServiceClient()

    # Build the parent key ring name.
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

    # Build the key.
    purpose = kms.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN
    algorithm = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256
    protection_level = kms.ProtectionLevel.HSM
    key = {
        'purpose': purpose,
        'version_template': {
            'algorithm': algorithm,
            'protection_level': protection_level,
        }
    }

    # Call the API.
    created_key = client.create_crypto_key(
        request={'parent': key_ring_name, 'crypto_key_id': key_id, 'crypto_key': key})
    print('Created asymmetric signing key: {}'.format(created_key.name))


def test_view_policy():
    client = kms.KeyManagementServiceClient()

    # Build the resource name.
    # resource_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

    # The resource name could also be a key ring.
    resource_name = client.key_ring_path(project_id, location_id, key_ring_id)

    # Get the current policy.
    policy = client.get_iam_policy(request={'resource': resource_name})

    # Print the policy
    print('IAM policy for {}'.format(resource_name))
    for binding in policy.bindings:
        print(binding.role)
        for mbr in binding.members:
            print('- {}'.format(mbr))


def test_set_policy():
    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the resource name.
    # resource_name = client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

    # The resource name could also be a key ring.
    resource_name = client.key_ring_path(project_id, location_id, key_ring_id)

    # Get the current policy.
    policy = client.get_iam_policy(request={'resource': resource_name})

    # Add the member to the policy.
    policy.bindings.add(
        role='roles/cloudkms.signer',
        members=[member])
    policy.bindings.add(
        role='roles/cloudkms.publicKeyViewer',
        members=[member])

    # Save the updated IAM policy.
    request = {
        'resource': resource_name,
        'policy': policy
    }

    updated_policy = client.set_iam_policy(request=request)
    print(f'Added {member} to {resource_name}: {updated_policy}')


def test_list_keyrings():
    client = kms.KeyManagementServiceClient()
    # Build the parent location name.
    location_name = f'projects/{project_id}/locations/{location_id}'

    # Call the API.
    key_rings = client.list_key_rings(request={'parent': location_name})

    # Example of iterating over key rings.
    for key_ring in key_rings:
        print(key_ring.name)


if __name__ == "__main__":
    # test_create_keyring()
    # test_create_key()
    # test_list_keyrings()
    # test_set_policy()
    # test_view_policy()
    # test_get_key()
    test_list_keys()
