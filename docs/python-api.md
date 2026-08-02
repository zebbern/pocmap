# Python API

Services are synchronous. Prefer using them as context managers in long-lived
processes (`with CVEService() as svc: ...`).

## CVE information

```python
from pocmap.services.cve_service import CVEService

cve_svc = CVEService()
info = cve_svc.get_cve_info("CVE-2021-44228")

print(info.id)                    # "CVE-2021-44228"
print(info.description)           # Full vulnerability description
print(info.cvss.base_score)       # 10.0
print(info.cvss.severity.value)   # "CRITICAL"
print(info.cvss.vector_string)    # "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
print(info.epss)                  # 97.53 (exploitation probability)
print(info.kev_status)            # True (in CISA KEV catalog)
print(info.cwes)                  # ["CWE-77", "CWE-94"]
print(info.vendor)                # "Apache"
print(info.product)               # "Log4j"
print(info.publication_date)      # "2021-12-10"
```

## Exploit discovery

Curated indexes first; when they miss (index-lag CVEs), GitHub repository search
is used as a fallback. Rate limits surface as `rate_limited`, never as empty.

```python
from pocmap.services.exploit_service import ExploitService

exploit_svc = ExploitService()

exploits = exploit_svc.find_exploits("CVE-2021-44228")
for ex in exploits:
    print(f"[{ex.source.value}] {ex.title}")
    print(f"  URL: {ex.url}")
    print(f"  Language: {ex.language} | Stars: {ex.stars} | Forks: {ex.forks}")

python_pocs = exploit_svc.filter_by_language(exploits, "Python")
go_pocs = exploit_svc.filter_by_language(exploits, "Go")

readme = exploit_svc.get_readme("https://github.com/example/poc")
```

For per-source health (`ok` / `empty` / `rate_limited` / `error`), use
`find_exploits_with_status` (same aggregation MCP reports use).

## Lab environments

```python
from pocmap.services.lab_service import LabService

lab_svc = LabService()
labs = lab_svc.find_labs("CVE-2021-44228")
for lab in labs:
    print(f"[{lab.platform.value}] {lab.name}: {lab.url}")
    if lab.setup_instructions:
        print(f"  Setup: {lab.setup_instructions}")
```

## Bug bounty reports

```python
from pocmap.services.bb_service import BugBountyService

bb_svc = BugBountyService()
reports = bb_svc.find_reports("CVE-2021-44228")
for report in reports:
    print(f"[{report.source.value}] {report.title}")
    print(f"  URL: {report.url} | PoC included: {report.has_poc}")
```

Hunter toolkit (checklists, workflows, templates, scope): [Bug Bounty Toolkit](bug-bounty.md).

## Report generation

```python
from pocmap.services.report_service import ReportService

report_svc = ReportService()

entry = report_svc.generate_report("CVE-2021-44228")
print(entry.to_json())

multi = report_svc.generate_bulk_report([
    "CVE-2021-44228",
    "CVE-2023-38408",
    "CVE-2024-21413",
])
report_svc.save_json_report(multi, "./output")
report_svc.save_html_report(multi, "./output")
```

## Schema export

```python
from pocmap.models import export_schemas

paths = export_schemas("./schemas")
# Generates: CVSSScore.json, CVEInfo.json, Exploit.json,
#            LabEnvironment.json, BugBountyReport.json,
#            CPEInfo.json, RecentExploitResult.json, ReportEntry.json,
#            MultiReport.json, VersionConstraint.json,
#            ProductDiscoveryResult.json,
#            PackageVulnerability.json, PackageDiscoveryResult.json
```

Also available as `pocmap schemas --output ./schemas`. Full schemas:
[Data model schemas](reference/schemas.md).
