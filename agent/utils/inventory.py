"""Assess normalized owner inventory without contacting or executing target code.

Usage: python -m agent.utils.inventory inventory.json
The input is an array of records in Asteroid's normalized evidence schema, NOT
a vendor API response. Callers must collect trustworthy release, deployment,
and effective configuration evidence for the same running target. This module
does not independently authenticate that evidence or verify backported fixes.
Only whitelisted assessment fields are emitted; supplied records are never echoed.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys
import typing
from collections.abc import Callable

from agent.exploits import cve_2025_64155 as fortisiem_assessment
from agent.exploits import cve_2025_3085 as cve_2025_3085_assessment
from agent.exploits import cve_2026_3593 as bind_doh_assessment
from agent.exploits import cve_2025_69258 as cve_2025_69258_assessment
from agent.exploits import cve_2026_8713 as avada_assessment
from agent.exploits import cve_2026_11374 as ad360_sso_assessment
from agent.exploits import cve_2026_20160 as ssm_assessment
from agent.exploits import cve_2026_8763 as bouncy_castle_name_assessment
from agent.exploits import cve_2026_20896 as gitea_proxy_assessment
from agent.exploits import cve_2026_59650 as bouncy_castle_dh_assessment
from agent.exploits import cve_2026_58062 as bouncy_castle_ocsp_assessment
from agent.exploits import cve_2026_89078 as gitlab_regexp_parser_assessment
from agent.exploits import cve_2026_93577 as gitlab_regexp_compiler_assessment
from agent.exploits import cve_2026_97229 as gitlab_cicd_assessment
from agent.exploits import cve_2026_107406 as cve_2026_107406_assessment
from agent.exploits import cve_2026_107656 as fortisandbox_assessment
from agent.exploits import cve_2026_110264 as gitlab_regexp_assessment
from agent.exploits import cve_2026_111497 as envoy_assessment
from agent.exploits import cve_2026_114625 as vco_assessment
from agent.exploits import cve_2026_115560 as php_assessment
from agent.utils import inventory_definitions
from agent.exploits import cve_2025_62581 as cve_2025_62581_assessment
from agent.exploits import cve_2026_3630 as cve_2026_3630_assessment
from agent.exploits import cve_2026_6516 as cve_2026_6516_assessment
from agent.exploits import cve_2026_74849 as cve_2026_74849_assessment
from agent.exploits import cve_2026_45674 as netty_dns_assessment
from agent.exploits import cve_2026_75595 as netty_sni_assessment
from agent.exploits import cve_2026_14446 as cve_2026_14446_assessment
from agent.exploits import cve_2026_16184 as cve_2026_16184_assessment
from agent.exploits import cve_2026_42530 as nginx_quic_assessment
from agent.exploits import cve_2026_8644 as cve_2026_8644_assessment
from agent.exploits import cve_2026_9319 as cve_2026_9319_assessment
from agent.exploits import cve_2026_11541 as cve_2026_11541_assessment
from agent.exploits import cve_2026_11546 as cve_2026_11546_assessment
from agent.exploits import cve_2026_42945 as nginx_rewrite_assessment
from agent.exploits import cve_2026_11714 as cve_2026_11714_assessment
from agent.exploits import cve_2026_14525 as cve_2026_14525_assessment
from agent.exploits import cve_2024_53298 as cve_2024_53298_assessment
from agent.exploits import cve_2026_8024 as cve_2026_8024_assessment
from agent.exploits import cve_2026_15176 as nginx_alias_assessment
from agent.exploits import cve_2025_62582 as cve_2025_62582_assessment
from agent.exploits import cve_2025_14917 as cve_2025_14917_assessment
from agent.exploits import cve_2025_14923 as cve_2025_14923_assessment
from agent.exploits import cve_2026_9006 as cve_2026_9006_assessment
from agent.exploits import cve_2026_42055 as nginx_upstream_assessment
from agent.exploits import cve_2026_4800 as lodash_imports_assessment
from agent.exploits import cve_2026_42533 as nginx_map_assessment
from agent.exploits import cve_2026_93479 as nginx_root_map_assessment
from agent.exploits import cve_2026_29000 as pac4j_jwt_assessment
from agent.exploits import cve_2026_0263 as panos_ikev2_assessment
from agent.exploits import cve_2026_0264 as panos_dns_assessment
from agent.exploits import cve_2023_42282 as node_ip_assessment
from agent.exploits import cve_2026_0265 as panos_cas_assessment
from agent.exploits import cve_2019_19006 as freepbx_framework_assessment
from agent.exploits import cve_2026_0300 as panos_portal_assessment
from agent.exploits import cve_2026_0288 as panos_tsa_assessment
from agent.exploits import cve_2026_48360 as adobe_connect_client_assessment
from agent.exploits import cve_2026_0310 as panos_xml_assessment
from agent.exploits import cve_2026_28323 as whd_saml_assessment
from agent.exploits import cve_2026_84411 as routeros_web_assessment
from agent.exploits import cve_2026_8364 as triofox_agent_assessment
from agent.exploits import cve_2026_67276 as routeros_ssh_assessment
from agent.exploits import cve_2024_9537 as sciencelogic_sl1_assessment
from agent.exploits import cve_2024_21591 as junos_jweb_assessment
from agent.exploits import cve_2021_31914 as teamcity_windows_assessment
from agent.exploits import cve_2026_102084 as junos_advpn_assessment
from agent.exploits import cve_2022_24331 as teamcity_gitlab_auth_assessment
from agent.exploits import cve_2026_76461 as cisco_email_assessment
from agent.exploits import cve_2025_20393 as cisco_quarantine_assessment
from agent.exploits import cve_2025_54531 as teamcity_plugin_assessment
from agent.exploits import cve_2026_20045 as cisco_voice_assessment
from agent.exploits import cve_2026_20093 as cisco_imc_assessment
from agent.exploits import cve_2026_87719 as gitlab_duo_assessment
from agent.exploits import cve_2026_76465 as cisco_mpls_assessment
from agent.exploits import cve_2026_76471 as cisco_nxapi_assessment
from agent.exploits import cve_2025_13761 as gitlab_browser_assessment
from agent.exploits import cve_2025_7659 as gitlab_ide_assessment
from agent.exploits import cve_2026_73453 as arista_p4_assessment
from agent.exploits import cve_2026_16627 as gitlab_job_modal_assessment
from agent.exploits import cve_2024_3596 as pan_radius_assessment
from agent.exploits import cve_2026_65637 as tomcat_sni_assessment
from agent.exploits import cve_2026_65905 as tomcat_digest_assessment
from agent.exploits import cve_2026_65182 as tomcat_constraint_assessment
from agent.exploits import cve_2026_68525 as tomcat_form_assessment
from agent.exploits import cve_2026_29145 as tomcat_ocsp_assessment

MAX_INVENTORY_BYTES = 1024 * 1024
# One product can carry several CVE assessors when their advisories disagree on
# boundaries; each keeps its own assessment and its own verdict.
_Assessor = Callable[[dict[str, object]], inventory_definitions.Assessment]
# One tuple of assessors shared by both GitLab product keys, so the CE and EE
# registrations can never drift apart when the next family CVE is added.
_GITLAB_ASSESSORS: tuple[_Assessor, ...] = (gitlab_regexp_parser_assessment.assess_record, gitlab_regexp_compiler_assessment.assess_record, gitlab_cicd_assessment.assess_record, gitlab_regexp_assessment.assess_record, gitlab_duo_assessment.assess_record, gitlab_browser_assessment.assess_record, gitlab_ide_assessment.assess_record, gitlab_job_modal_assessment.assess_record)
_ASSESSORS: dict[str, tuple[_Assessor, ...]] = {'FortiSIEM': (fortisiem_assessment.assess_record,), 'BC-JAVA': (bouncy_castle_ocsp_assessment.assess_record,), 'BC-LTS-JAVA': (bouncy_castle_ocsp_assessment.assess_record,), 'BC-FJA': (bouncy_castle_ocsp_assessment.assess_record,), 'FortiSandbox': (fortisandbox_assessment.assess_record,), 'FortiSandbox PaaS': (fortisandbox_assessment.assess_record,), 'Cisco Smart Software Manager On-Prem': (ssm_assessment.assess_record,), 'ISC BIND 9': (bind_doh_assessment.assess_record,), 'Avada Builder': (avada_assessment.assess_record,), 'VeloCloud Orchestrator': (vco_assessment.assess_record,), 'GitLab CE': _GITLAB_ASSESSORS, 'GitLab EE': _GITLAB_ASSESSORS, 'PHP': (php_assessment.assess_record,), 'Gitea': (gitea_proxy_assessment.assess_record,), 'Envoy': (envoy_assessment.assess_record,), 'ManageEngine ADSelfService Plus': (ad360_sso_assessment.assess_record,), 'ManageEngine RecoveryManager Plus': (ad360_sso_assessment.assess_record,), 'ManageEngine M365 Manager Plus': (ad360_sso_assessment.assess_record,), 'ManageEngine ADAudit Plus': (ad360_sso_assessment.assess_record,), 'io.netty:netty-resolver-dns': (netty_dns_assessment.assess_record,), 'io.netty:netty-handler': (netty_sni_assessment.assess_record,), 'NGINX Open Source': (nginx_quic_assessment.assess_record, nginx_rewrite_assessment.assess_record, nginx_alias_assessment.assess_record, nginx_upstream_assessment.assess_record, nginx_map_assessment.assess_record, nginx_root_map_assessment.assess_record), 'npm:lodash': (lodash_imports_assessment.assess_record,), 'npm:lodash-es': (lodash_imports_assessment.assess_record,), 'npm:lodash-amd': (lodash_imports_assessment.assess_record,), 'npm:lodash.template': (lodash_imports_assessment.assess_record,), 'org.pac4j:pac4j-jwt': (pac4j_jwt_assessment.assess_record,), 'PAN-OS': (panos_ikev2_assessment.assess_record, panos_dns_assessment.assess_record, panos_cas_assessment.assess_record, panos_portal_assessment.assess_record, panos_tsa_assessment.assess_record, panos_xml_assessment.assess_record, pan_radius_assessment.assess_record), 'npm:ip': (node_ip_assessment.assess_record,), 'FreePBX Framework': (freepbx_framework_assessment.assess_record,), 'Adobe Connect Desktop App': (adobe_connect_client_assessment.assess_record,), 'Adobe Connect Android Mobile App': (adobe_connect_client_assessment.assess_record,), 'SolarWinds Web Help Desk': (whd_saml_assessment.assess_record,), 'MikroTik RouterOS': (routeros_web_assessment.assess_record, routeros_ssh_assessment.assess_record), 'Triofox Server Agent': (triofox_agent_assessment.assess_record,), 'ScienceLogic SL1': (sciencelogic_sl1_assessment.assess_record,), 'Junos OS': (junos_jweb_assessment.assess_record, junos_advpn_assessment.assess_record), 'Cisco Secure Email Gateway': (cisco_email_assessment.assess_record, cisco_quarantine_assessment.assess_record), 'Cisco Secure Email and Web Manager': (cisco_quarantine_assessment.assess_record,), 'Cisco Unified Communications Manager': (cisco_voice_assessment.assess_record,), 'Cisco Unified Communications Manager IM and Presence Service': (cisco_voice_assessment.assess_record,), 'Cisco Unity Connection': (cisco_voice_assessment.assess_record,), 'Cisco Unified Communications Manager Session Management Edition': (cisco_voice_assessment.assess_record,), 'Cisco Integrated Management Controller': (cisco_imc_assessment.assess_record,), 'Cisco NX-OS': (cisco_mpls_assessment.assess_record, cisco_nxapi_assessment.assess_record), 'Cisco UCS Manager': (cisco_nxapi_assessment.assess_record,), 'Arista EOS': (arista_p4_assessment.assess_record,)}

# CVE-2026-107406 owner-inventory registration.
_ASSESSORS["NetScaler ADC"] = (
    *_ASSESSORS.get("NetScaler ADC", ()),
    cve_2026_107406_assessment.assess_record,
)
_ASSESSORS["NetScaler Gateway"] = (
    *_ASSESSORS.get("NetScaler Gateway", ()),
    cve_2026_107406_assessment.assess_record,
)


# Append so separately merged Bouncy Castle CVEs retain their own assessments.
for _bouncy_castle_product in ("BC-JAVA", "BC-LTS-JAVA"):
    _ASSESSORS[_bouncy_castle_product] = (
        *_ASSESSORS.get(_bouncy_castle_product, ()),
        bouncy_castle_dh_assessment.assess_record,
    )
# CVE-2025-3085 owner-inventory registration.
_ASSESSORS["MongoDB Server"] = (
    *_ASSESSORS.get("MongoDB Server", ()),
    cve_2025_3085_assessment.assess_record,
)


# Preserve other provider assessments when independently added CVEs are combined.
for _bouncy_castle_product in ("BC-JAVA", "BC-LTS-JAVA", "BC-FJA"):
    _ASSESSORS[_bouncy_castle_product] = (
        *_ASSESSORS.get(_bouncy_castle_product, ()),
        bouncy_castle_name_assessment.assess_record,
    )
# CVE-2025-69258 owner-inventory registration.
_ASSESSORS["Trend Micro Apex Central"] = (
    *_ASSESSORS.get("Trend Micro Apex Central", ()),
    cve_2025_69258_assessment.assess_record,
)


_ASSESSORS["Delta Electronics DIAView"] = (
    *_ASSESSORS.get("Delta Electronics DIAView", ()),
    cve_2025_62581_assessment.assess_record,
)


_ASSESSORS["Delta Electronics COMMGR 2"] = (
    *_ASSESSORS.get("Delta Electronics COMMGR 2", ()),
    cve_2026_3630_assessment.assess_record,
)


_ASSESSORS["ManageEngine ADAudit Plus"] = (
    *_ASSESSORS.get("ManageEngine ADAudit Plus", ()),
    cve_2026_6516_assessment.assess_record,
)


_ASSESSORS["ManageEngine ADSelfService Plus"] = (
    *_ASSESSORS.get("ManageEngine ADSelfService Plus", ()),
    cve_2026_74849_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server", ()),
    cve_2026_14446_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server", ()),
    cve_2026_16184_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server", ()),
    cve_2026_8644_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server", ()),
    cve_2026_9319_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server", ()),
    cve_2026_11541_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server Liberty"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server Liberty", ()),
    cve_2026_11546_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server Liberty"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server Liberty", ()),
    cve_2026_11714_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server Liberty"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server Liberty", ()),
    cve_2026_14525_assessment.assess_record,
)


_ASSESSORS["Dell PowerScale OneFS"] = (
    *_ASSESSORS.get("Dell PowerScale OneFS", ()),
    cve_2024_53298_assessment.assess_record,
)


_ASSESSORS["ibaPDA"] = (
    *_ASSESSORS.get("ibaPDA", ()),
    cve_2026_8024_assessment.assess_record,
)

_ASSESSORS["ibaDatCoordinator"] = (
    *_ASSESSORS.get("ibaDatCoordinator", ()),
    cve_2026_8024_assessment.assess_record,
)

_ASSESSORS["ibaLogic"] = (
    *_ASSESSORS.get("ibaLogic", ()),
    cve_2026_8024_assessment.assess_record,
)


_ASSESSORS["Delta Electronics DIAView"] = (
    *_ASSESSORS.get("Delta Electronics DIAView", ()),
    cve_2025_62582_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server Liberty"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server Liberty", ()),
    cve_2025_14917_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server Liberty"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server Liberty", ()),
    cve_2025_14923_assessment.assess_record,
)


_ASSESSORS["IBM WebSphere Application Server"] = (
    *_ASSESSORS.get("IBM WebSphere Application Server", ()),
    cve_2026_9006_assessment.assess_record,
)


_ASSESSORS["JetBrains TeamCity"] = (
    *_ASSESSORS.get("JetBrains TeamCity", ()),
    teamcity_windows_assessment.assess_record,
)


_ASSESSORS["JetBrains TeamCity"] = (
    *_ASSESSORS.get("JetBrains TeamCity", ()),
    teamcity_gitlab_auth_assessment.assess_record,
)


_ASSESSORS["JetBrains TeamCity"] = (
    *_ASSESSORS.get("JetBrains TeamCity", ()),
    teamcity_plugin_assessment.assess_record,
)


_ASSESSORS["Apache Tomcat"] = (
    *_ASSESSORS.get("Apache Tomcat", ()),
    tomcat_sni_assessment.assess_record,
)


_ASSESSORS["Apache Tomcat"] = (
    *_ASSESSORS.get("Apache Tomcat", ()),
    tomcat_digest_assessment.assess_record,
)


_ASSESSORS["Apache Tomcat"] = (
    *_ASSESSORS.get("Apache Tomcat", ()),
    tomcat_constraint_assessment.assess_record,
)


_ASSESSORS["Apache Tomcat"] = (
    *_ASSESSORS.get("Apache Tomcat", ()),
    tomcat_form_assessment.assess_record,
)


for _product in tomcat_ocsp_assessment.PRODUCTS:
    _ASSESSORS[_product] = (
        *_ASSESSORS.get(_product, ()),
        tomcat_ocsp_assessment.assess_record,
    )


def assess_records(record: dict[str, object]) -> list[inventory_definitions.Assessment]:
    """Dispatch normalized owner evidence to the product's CVE assessments."""
    product = record.get("product")
    if isinstance(product, str) is False or product not in _ASSESSORS:
        return [
            inventory_definitions.Assessment(
                (),
                "inconclusive",
                "Unsupported or missing product identity.",
                "Verify the product and consult its vendor advisory.",
            )
        ]
    return [assess(record) for assess in _ASSESSORS[product]]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate inventory field")
        result[key] = value
    return result


def _reject_constant(value: str) -> typing.NoReturn:
    raise ValueError("Non-standard JSON constant")


def main(argv: list[str] | None = None) -> int:
    """Read bounded JSON inventory and emit sanitized assessments, with no target I/O."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        with args.inventory.open("rb") as inventory_file:
            content = inventory_file.read(MAX_INVENTORY_BYTES + 1)
        if len(content) > MAX_INVENTORY_BYTES:
            raise ValueError("Inventory too large")
        records = json.loads(
            content, object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        if isinstance(records, list) is False or any(
            isinstance(record, dict) is False for record in records
        ):
            raise ValueError("Inventory must be an array of records")
        assessments = [
            dataclasses.asdict(assessment)
            for record in records
            for assessment in assess_records(record)
        ]
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("Invalid inventory file.", file=sys.stderr)
        return 2
    print(json.dumps(assessments))
    return 0


if __name__ == "__main__":
    sys.exit(main())
