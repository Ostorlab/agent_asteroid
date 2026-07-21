"""Safe example: inline lookup with organisation scope.

Mirrors RescanMutation (reporting_engine/schemas/authenticated.py) inline form.
Should NOT be flagged.
"""

import re_models
import authentication


def create_rescan(root, info, scan_id=None):
    """Protected inline resolver."""
    (
        organisation,
        org_user,
        org_api_key,
    ) = authentication.get_organisation_from_context(info)

    scan = re_models.Scan.objects.get(id=scan_id, organisation=organisation)
    return {"result": True}


def vulnerable_inline(root, info, scan_id=None):
    """Vulnerable inline resolver: id-only, no organisation."""
    (
        organisation,
        org_user,
        org_api_key,
    ) = authentication.get_organisation_from_context(info)

    scan = re_models.Scan.objects.get(id=scan_id)
    return {"result": True}
