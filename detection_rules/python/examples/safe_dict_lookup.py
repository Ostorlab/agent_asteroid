"""Safe example: organisation scope present on scan resolution.

Mirrors StopScanMutation.mutate (reporting_engine/schemas/authenticated.py).
Should NOT be flagged.
"""

import re_models
import authentication


def stop_scan(root, info, scan_id=None):
    """Protected mutate resolver."""
    (
        organisation,
        org_user,
        org_api_key,
    ) = authentication.get_organisation_from_context(info)

    filters = {
        "id": scan_id,
        "organisation": organisation,
    }
    if organisation.settings.has_object_level_access is True:
        if org_user is not None and org_user.is_admin(organisation) is False:
            filters["cached_user_accesses__user"] = org_user
        elif org_api_key is not None and org_api_key.role != "admin":
            filters["cached_api_key_accesses__api_key"] = org_api_key

    scan = re_models.Scan.objects.get(**filters)
    return {"result": True}
