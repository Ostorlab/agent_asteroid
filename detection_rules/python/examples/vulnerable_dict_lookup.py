"""Vulnerable example: missing organisation scope on scan resolution.

Mirrors CustomizeVulnerabilitiesMutation.mutate (reporting_engine/schemas/authenticated.py).
Should be flagged by ostorlab.django.tenant-scoped-orm-lookup.missing-organisation-key.
"""

import re_models
import authentication


def mutate(root, info, scan_id=None, vulnerability_ids=None, custom_risk_rating=None):
    """Vulnerable mutate resolver."""
    (
        organisation,
        org_user,
        org_api_key,
    ) = authentication.get_organisation_from_context(info)

    scans = set()

    if scan_id is not None:
        filters = {
            "id": scan_id,
        }
        if organisation.settings.has_object_level_access is True:
            if org_user is not None and org_user.is_admin(organisation) is False:
                filters["cached_user_accesses__user"] = org_user
            elif org_api_key is not None and org_api_key.role != "admin":
                filters["cached_api_key_accesses__api_key"] = org_api_key

        scan = re_models.Scan.objects.get(**filters)
        scans.add(scan)

    return {"result": True}
