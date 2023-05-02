from gcp_ksm_shim.core import keeping


def module(projectId, locationId, keyRingId):
    return keeping.Module(projectId, locationId, keyRingId)