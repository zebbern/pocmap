# Data model schemas

JSON Schema (Pydantic serialization mode) for the main PocMap models. Regenerate with `python scripts/generate_mcp_docs.py`, or write all schemas to disk via `pocmap schemas --output ./schemas`.

MCP tools return plain objects under an open `{"type": "object"}` output schema so error envelopes are never stamped with success defaults.

## `CVEInfo`

```json
{
  "$defs": {
    "AffectedProduct": {
      "description": "One ``(vendor, product)`` pair a CVE is recorded against.\n\nA single CVE routinely names several: the vulnerable component plus every\ndistribution that shipped it (e.g. ``f5:nginx`` alongside\n``fedoraproject:fedora``). Matching must consider all of them \u2014 collapsing\nto a single pair silently drops the component the CVE is actually about.\n\nAttributes:\n    vendor: Vendor name as it appears in the CPE (already lowercased by NVD).\n    product: Product name as it appears in the CPE.",
      "properties": {
        "vendor": {
          "description": "Vendor name from the CPE",
          "title": "Vendor",
          "type": "string"
        },
        "product": {
          "description": "Product name from the CPE",
          "title": "Product",
          "type": "string"
        }
      },
      "required": [
        "vendor",
        "product"
      ],
      "title": "AffectedProduct",
      "type": "object"
    },
    "CPEMatch": {
      "description": "A CPE applicability statement, including its version bounds.\n\nModern NVD entries express affected version *ranges* out-of-band: the CPE\n``criteria`` carries ``*`` in the version field and the real range lives in\nthe ``versionStart*`` / ``versionEnd*`` attributes. Reading only the literal\nversion field therefore matches everything.\n\nAttributes:\n    criteria: The CPE 2.3 string.\n    version_start_including: Inclusive lower bound, if any.\n    version_start_excluding: Exclusive lower bound, if any.\n    version_end_including: Inclusive upper bound, if any.\n    version_end_excluding: Exclusive upper bound, if any.\n    vulnerable: Whether NVD marks this CPE as vulnerable (vs. merely a platform).",
      "properties": {
        "criteria": {
          "description": "CPE 2.3 string",
          "title": "Criteria",
          "type": "string"
        },
        "version_start_including": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Inclusive lower version bound",
          "title": "Version Start Including"
        },
        "version_start_excluding": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Exclusive lower version bound",
          "title": "Version Start Excluding"
        },
        "version_end_including": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Inclusive upper version bound",
          "title": "Version End Including"
        },
        "version_end_excluding": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Exclusive upper version bound",
          "title": "Version End Excluding"
        },
        "vulnerable": {
          "default": true,
          "description": "Whether NVD marks this CPE vulnerable",
          "title": "Vulnerable",
          "type": "boolean"
        }
      },
      "required": [
        "criteria"
      ],
      "title": "CPEMatch",
      "type": "object"
    },
    "CVEState": {
      "description": "Publication states for a CVE identifier.",
      "enum": [
        "PUBLISHED",
        "RESERVED",
        "REJECTED",
        "UNKNOWN"
      ],
      "title": "CVEState",
      "type": "string"
    },
    "CVSSScore": {
      "description": "CVSS scoring information for a vulnerability.\n\nAttributes:\n    version: CVSS specification version (e.g., \"3.1\").\n    base_score: Numeric base score (0.0 -- 10.0).\n    severity: Human-readable severity level.\n    vector_string: Compressed CVSS vector string.",
      "properties": {
        "version": {
          "$ref": "#/$defs/CVSSVersion",
          "default": "unknown",
          "description": "CVSS version"
        },
        "base_score": {
          "anyOf": [
            {
              "maximum": 10.0,
              "minimum": 0.0,
              "type": "number"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "CVSS base score",
          "title": "Base Score"
        },
        "severity": {
          "$ref": "#/$defs/Severity",
          "default": "UNKNOWN",
          "description": "Severity level"
        },
        "vector_string": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "CVSS vector string",
          "title": "Vector String"
        }
      },
      "title": "CVSSScore",
      "type": "object"
    },
    "CVSSVersion": {
      "description": "Supported CVSS version identifiers.",
      "enum": [
        "2.0",
        "3.0",
        "3.1",
        "4.0",
        "unknown"
      ],
      "title": "CVSSVersion",
      "type": "string"
    },
    "Severity": {
      "description": "CVSS severity levels.",
      "enum": [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN"
      ],
      "title": "Severity",
      "type": "string"
    }
  },
  "description": "Comprehensive CVE (Common Vulnerabilities and Exposures) record.\n\nAttributes:\n    id: The CVE identifier (e.g., ``CVE-2021-44228``).\n    description: Human-readable vulnerability description.\n    cvss: CVSS scoring information.\n    epss: Exploit Prediction Scoring System score (0.0 -- 100.0).\n    kev_status: Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog.\n    cwes: List of associated CWE (Common Weakness Enumeration) identifiers.\n    references: Dictionary of reference names to URLs.\n    vendor: Affected vendor name.\n    product: Affected product name.\n    publication_date: Date the CVE was published.\n    state: Current publication state.\n    ransomware_usage: Whether the CVE is known to be used in ransomware campaigns.",
  "properties": {
    "id": {
      "description": "CVE identifier",
      "pattern": "^CVE-\\d{4}-\\d+$",
      "title": "Id",
      "type": "string"
    },
    "description": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Vulnerability description",
      "title": "Description"
    },
    "cvss": {
      "anyOf": [
        {
          "$ref": "#/$defs/CVSSScore"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "CVSS score information"
    },
    "epss": {
      "anyOf": [
        {
          "maximum": 100.0,
          "minimum": 0.0,
          "type": "number"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "EPSS score (0-100)",
      "title": "Epss"
    },
    "kev_status": {
      "default": false,
      "description": "CISA KEV status",
      "title": "Kev Status",
      "type": "boolean"
    },
    "cwes": {
      "description": "Associated CWEs",
      "items": {
        "type": "string"
      },
      "title": "Cwes",
      "type": "array"
    },
    "references": {
      "additionalProperties": {
        "type": "string"
      },
      "description": "Reference URLs",
      "title": "References",
      "type": "object"
    },
    "vendor": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Vendor name",
      "title": "Vendor"
    },
    "product": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Product name",
      "title": "Product"
    },
    "publication_date": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Publication date",
      "title": "Publication Date"
    },
    "state": {
      "$ref": "#/$defs/CVEState",
      "default": "UNKNOWN",
      "description": "CVE state"
    },
    "ransomware_usage": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Ransomware campaign usage status",
      "title": "Ransomware Usage"
    },
    "rejected_reason": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Reason for rejection (if state is REJECTED)",
      "title": "Rejected Reason"
    },
    "affected_cpes": {
      "description": "Affected CPE 2.3 strings extracted from NVD data",
      "items": {
        "type": "string"
      },
      "title": "Affected Cpes",
      "type": "array"
    },
    "affected_products": {
      "description": "Every (vendor, product) pair the CVE is recorded against. ``vendor``/``product`` above are the first of these, kept for compatibility.",
      "items": {
        "$ref": "#/$defs/AffectedProduct"
      },
      "title": "Affected Products",
      "type": "array"
    },
    "cpe_matches": {
      "description": "Full CPE applicability statements, including version bounds",
      "items": {
        "$ref": "#/$defs/CPEMatch"
      },
      "title": "Cpe Matches",
      "type": "array"
    }
  },
  "required": [
    "id"
  ],
  "title": "CVEInfo",
  "type": "object"
}
```

## `Exploit`

```json
{
  "$defs": {
    "ExploitSource": {
      "description": "Known sources for exploit code.",
      "enum": [
        "github",
        "exploitdb",
        "metasploit",
        "nuclei",
        "trickest",
        "nomi-sec",
        "other"
      ],
      "title": "ExploitSource",
      "type": "string"
    },
    "MSFRank": {
      "description": "Metasploit exploit reliability ranking.",
      "enum": [
        "excellent",
        "great",
        "good",
        "normal",
        "average",
        "low",
        "manual",
        "unknown"
      ],
      "title": "MSFRank",
      "type": "string"
    }
  },
  "description": "A single exploit / PoC entry.\n\nAttributes:\n    source: Where the exploit was found.\n    url: Direct URL to the exploit code or repository.\n    title: Human-readable title or description.\n    language: Primary programming language (if known).\n    stars: GitHub star count (if applicable).\n    forks: GitHub fork count (if applicable).\n    rank: Metasploit exploit rank (if applicable).\n    labels: Heuristic quality labels (scanner/poc/writeup/\u2026).\n    last_commit: ISO timestamp of last push (GitHub), when known.\n    trust_score: Heuristic trust in ``[0.0, 1.0]``.\n    module_path: Metasploit module filesystem path, when known.\n    module_type: Metasploit module type (exploit/auxiliary/\u2026), when known.\n    platform: Metasploit target platform list/string, when known.",
  "properties": {
    "source": {
      "$ref": "#/$defs/ExploitSource",
      "description": "Exploit source"
    },
    "url": {
      "description": "URL to exploit",
      "title": "Url",
      "type": "string"
    },
    "title": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Exploit title",
      "title": "Title"
    },
    "language": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Programming language",
      "title": "Language"
    },
    "stars": {
      "anyOf": [
        {
          "minimum": 0,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "GitHub stars",
      "title": "Stars"
    },
    "forks": {
      "anyOf": [
        {
          "minimum": 0,
          "type": "integer"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "GitHub forks",
      "title": "Forks"
    },
    "rank": {
      "anyOf": [
        {
          "$ref": "#/$defs/MSFRank"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Metasploit rank"
    },
    "command": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "CLI command to run the exploit (e.g., msfconsole command)",
      "title": "Command"
    },
    "labels": {
      "description": "Heuristic PoC quality labels (scanner, poc, writeup, \u2026)",
      "items": {
        "type": "string"
      },
      "title": "Labels",
      "type": "array"
    },
    "last_commit": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Last repository push time (ISO-8601), when known",
      "title": "Last Commit"
    },
    "trust_score": {
      "anyOf": [
        {
          "maximum": 1.0,
          "minimum": 0.0,
          "type": "number"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Heuristic trust score in [0.0, 1.0]",
      "title": "Trust Score"
    },
    "module_path": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Metasploit module path on disk, when known",
      "title": "Module Path"
    },
    "module_type": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Metasploit module type (exploit, auxiliary, \u2026)",
      "title": "Module Type"
    },
    "platform": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Metasploit platform target(s), when known",
      "title": "Platform"
    }
  },
  "required": [
    "source",
    "url"
  ],
  "title": "Exploit",
  "type": "object"
}
```

## `LabEnvironment`

```json
{
  "$defs": {
    "LabPlatform": {
      "description": "Platforms hosting CTF/lab environments.",
      "enum": [
        "hackthebox",
        "tryhackme",
        "vulhub",
        "other"
      ],
      "title": "LabPlatform",
      "type": "string"
    }
  },
  "description": "A CTF lab or pre-built vulnerable Docker environment.\n\nAttributes:\n    platform: Hosting platform (HackTheBox, TryHackMe, Vulhub).\n    name: Room/machine/environment name.\n    url: Direct URL to access the lab.\n    setup_instructions: Step-by-step setup guide (for Vulhub).",
  "properties": {
    "platform": {
      "$ref": "#/$defs/LabPlatform",
      "description": "Lab platform"
    },
    "name": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Lab name",
      "title": "Name"
    },
    "url": {
      "description": "Lab URL",
      "title": "Url",
      "type": "string"
    },
    "setup_instructions": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Setup instructions for local environments",
      "title": "Setup Instructions"
    }
  },
  "required": [
    "platform",
    "url"
  ],
  "title": "LabEnvironment",
  "type": "object"
}
```

## `BugBountyReport`

```json
{
  "$defs": {
    "BugBountySource": {
      "description": "Sources for bug bounty write-ups.",
      "enum": [
        "hackerone",
        "pentesterland",
        "bugbounty_hunting",
        "other"
      ],
      "title": "BugBountySource",
      "type": "string"
    }
  },
  "description": "A bug bounty write-up or disclosure report.\n\nAttributes:\n    source: Platform where the report was published.\n    url: Direct URL to the report.\n    has_poc: Whether the report includes a PoC demonstration.\n    title: Report title.",
  "properties": {
    "source": {
      "$ref": "#/$defs/BugBountySource",
      "description": "Report source"
    },
    "url": {
      "description": "Report URL",
      "title": "Url",
      "type": "string"
    },
    "has_poc": {
      "anyOf": [
        {
          "type": "boolean"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Whether a PoC is included",
      "title": "Has Poc"
    },
    "title": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Report title",
      "title": "Title"
    }
  },
  "required": [
    "source",
    "url"
  ],
  "title": "BugBountyReport",
  "type": "object"
}
```

## `CPEInfo`

```json
{
  "description": "Common Platform Enumeration (CPE) identifier.\n\nAttributes:\n    cpe_string: Full CPE 2.3 URI (e.g., ``cpe:2.3:o:microsoft:windows_10:1607``).\n    vendor: Software/hardware vendor name.\n    product: Product name.\n    version: Product version string.",
  "properties": {
    "cpe_string": {
      "description": "Full CPE 2.3 string",
      "title": "Cpe String",
      "type": "string"
    },
    "vendor": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Vendor name",
      "title": "Vendor"
    },
    "product": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Product name",
      "title": "Product"
    },
    "version": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Product version",
      "title": "Version"
    }
  },
  "required": [
    "cpe_string"
  ],
  "title": "CPEInfo",
  "type": "object"
}
```

## `ReportEntry`

```json
{
  "$defs": {
    "AffectedProduct": {
      "description": "One ``(vendor, product)`` pair a CVE is recorded against.\n\nA single CVE routinely names several: the vulnerable component plus every\ndistribution that shipped it (e.g. ``f5:nginx`` alongside\n``fedoraproject:fedora``). Matching must consider all of them \u2014 collapsing\nto a single pair silently drops the component the CVE is actually about.\n\nAttributes:\n    vendor: Vendor name as it appears in the CPE (already lowercased by NVD).\n    product: Product name as it appears in the CPE.",
      "properties": {
        "vendor": {
          "description": "Vendor name from the CPE",
          "title": "Vendor",
          "type": "string"
        },
        "product": {
          "description": "Product name from the CPE",
          "title": "Product",
          "type": "string"
        }
      },
      "required": [
        "vendor",
        "product"
      ],
      "title": "AffectedProduct",
      "type": "object"
    },
    "BugBountyReport": {
      "description": "A bug bounty write-up or disclosure report.\n\nAttributes:\n    source: Platform where the report was published.\n    url: Direct URL to the report.\n    has_poc: Whether the report includes a PoC demonstration.\n    title: Report title.",
      "properties": {
        "source": {
          "$ref": "#/$defs/BugBountySource",
          "description": "Report source"
        },
        "url": {
          "description": "Report URL",
          "title": "Url",
          "type": "string"
        },
        "has_poc": {
          "anyOf": [
            {
              "type": "boolean"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Whether a PoC is included",
          "title": "Has Poc"
        },
        "title": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Report title",
          "title": "Title"
        }
      },
      "required": [
        "source",
        "url"
      ],
      "title": "BugBountyReport",
      "type": "object"
    },
    "BugBountySource": {
      "description": "Sources for bug bounty write-ups.",
      "enum": [
        "hackerone",
        "pentesterland",
        "bugbounty_hunting",
        "other"
      ],
      "title": "BugBountySource",
      "type": "string"
    },
    "CPEMatch": {
      "description": "A CPE applicability statement, including its version bounds.\n\nModern NVD entries express affected version *ranges* out-of-band: the CPE\n``criteria`` carries ``*`` in the version field and the real range lives in\nthe ``versionStart*`` / ``versionEnd*`` attributes. Reading only the literal\nversion field therefore matches everything.\n\nAttributes:\n    criteria: The CPE 2.3 string.\n    version_start_including: Inclusive lower bound, if any.\n    version_start_excluding: Exclusive lower bound, if any.\n    version_end_including: Inclusive upper bound, if any.\n    version_end_excluding: Exclusive upper bound, if any.\n    vulnerable: Whether NVD marks this CPE as vulnerable (vs. merely a platform).",
      "properties": {
        "criteria": {
          "description": "CPE 2.3 string",
          "title": "Criteria",
          "type": "string"
        },
        "version_start_including": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Inclusive lower version bound",
          "title": "Version Start Including"
        },
        "version_start_excluding": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Exclusive lower version bound",
          "title": "Version Start Excluding"
        },
        "version_end_including": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Inclusive upper version bound",
          "title": "Version End Including"
        },
        "version_end_excluding": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Exclusive upper version bound",
          "title": "Version End Excluding"
        },
        "vulnerable": {
          "default": true,
          "description": "Whether NVD marks this CPE vulnerable",
          "title": "Vulnerable",
          "type": "boolean"
        }
      },
      "required": [
        "criteria"
      ],
      "title": "CPEMatch",
      "type": "object"
    },
    "CVEInfo": {
      "description": "Comprehensive CVE (Common Vulnerabilities and Exposures) record.\n\nAttributes:\n    id: The CVE identifier (e.g., ``CVE-2021-44228``).\n    description: Human-readable vulnerability description.\n    cvss: CVSS scoring information.\n    epss: Exploit Prediction Scoring System score (0.0 -- 100.0).\n    kev_status: Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog.\n    cwes: List of associated CWE (Common Weakness Enumeration) identifiers.\n    references: Dictionary of reference names to URLs.\n    vendor: Affected vendor name.\n    product: Affected product name.\n    publication_date: Date the CVE was published.\n    state: Current publication state.\n    ransomware_usage: Whether the CVE is known to be used in ransomware campaigns.",
      "properties": {
        "id": {
          "description": "CVE identifier",
          "pattern": "^CVE-\\d{4}-\\d+$",
          "title": "Id",
          "type": "string"
        },
        "description": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Vulnerability description",
          "title": "Description"
        },
        "cvss": {
          "anyOf": [
            {
              "$ref": "#/$defs/CVSSScore"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "CVSS score information"
        },
        "epss": {
          "anyOf": [
            {
              "maximum": 100.0,
              "minimum": 0.0,
              "type": "number"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "EPSS score (0-100)",
          "title": "Epss"
        },
        "kev_status": {
          "default": false,
          "description": "CISA KEV status",
          "title": "Kev Status",
          "type": "boolean"
        },
        "cwes": {
          "description": "Associated CWEs",
          "items": {
            "type": "string"
          },
          "title": "Cwes",
          "type": "array"
        },
        "references": {
          "additionalProperties": {
            "type": "string"
          },
          "description": "Reference URLs",
          "title": "References",
          "type": "object"
        },
        "vendor": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Vendor name",
          "title": "Vendor"
        },
        "product": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Product name",
          "title": "Product"
        },
        "publication_date": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Publication date",
          "title": "Publication Date"
        },
        "state": {
          "$ref": "#/$defs/CVEState",
          "default": "UNKNOWN",
          "description": "CVE state"
        },
        "ransomware_usage": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Ransomware campaign usage status",
          "title": "Ransomware Usage"
        },
        "rejected_reason": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Reason for rejection (if state is REJECTED)",
          "title": "Rejected Reason"
        },
        "affected_cpes": {
          "description": "Affected CPE 2.3 strings extracted from NVD data",
          "items": {
            "type": "string"
          },
          "title": "Affected Cpes",
          "type": "array"
        },
        "affected_products": {
          "description": "Every (vendor, product) pair the CVE is recorded against. ``vendor``/``product`` above are the first of these, kept for compatibility.",
          "items": {
            "$ref": "#/$defs/AffectedProduct"
          },
          "title": "Affected Products",
          "type": "array"
        },
        "cpe_matches": {
          "description": "Full CPE applicability statements, including version bounds",
          "items": {
            "$ref": "#/$defs/CPEMatch"
          },
          "title": "Cpe Matches",
          "type": "array"
        }
      },
      "required": [
        "id"
      ],
      "title": "CVEInfo",
      "type": "object"
    },
    "CVEState": {
      "description": "Publication states for a CVE identifier.",
      "enum": [
        "PUBLISHED",
        "RESERVED",
        "REJECTED",
        "UNKNOWN"
      ],
      "title": "CVEState",
      "type": "string"
    },
    "CVSSScore": {
      "description": "CVSS scoring information for a vulnerability.\n\nAttributes:\n    version: CVSS specification version (e.g., \"3.1\").\n    base_score: Numeric base score (0.0 -- 10.0).\n    severity: Human-readable severity level.\n    vector_string: Compressed CVSS vector string.",
      "properties": {
        "version": {
          "$ref": "#/$defs/CVSSVersion",
          "default": "unknown",
          "description": "CVSS version"
        },
        "base_score": {
          "anyOf": [
            {
              "maximum": 10.0,
              "minimum": 0.0,
              "type": "number"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "CVSS base score",
          "title": "Base Score"
        },
        "severity": {
          "$ref": "#/$defs/Severity",
          "default": "UNKNOWN",
          "description": "Severity level"
        },
        "vector_string": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "CVSS vector string",
          "title": "Vector String"
        }
      },
      "title": "CVSSScore",
      "type": "object"
    },
    "CVSSVersion": {
      "description": "Supported CVSS version identifiers.",
      "enum": [
        "2.0",
        "3.0",
        "3.1",
        "4.0",
        "unknown"
      ],
      "title": "CVSSVersion",
      "type": "string"
    },
    "Exploit": {
      "description": "A single exploit / PoC entry.\n\nAttributes:\n    source: Where the exploit was found.\n    url: Direct URL to the exploit code or repository.\n    title: Human-readable title or description.\n    language: Primary programming language (if known).\n    stars: GitHub star count (if applicable).\n    forks: GitHub fork count (if applicable).\n    rank: Metasploit exploit rank (if applicable).\n    labels: Heuristic quality labels (scanner/poc/writeup/\u2026).\n    last_commit: ISO timestamp of last push (GitHub), when known.\n    trust_score: Heuristic trust in ``[0.0, 1.0]``.\n    module_path: Metasploit module filesystem path, when known.\n    module_type: Metasploit module type (exploit/auxiliary/\u2026), when known.\n    platform: Metasploit target platform list/string, when known.",
      "properties": {
        "source": {
          "$ref": "#/$defs/ExploitSource",
          "description": "Exploit source"
        },
        "url": {
          "description": "URL to exploit",
          "title": "Url",
          "type": "string"
        },
        "title": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Exploit title",
          "title": "Title"
        },
        "language": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Programming language",
          "title": "Language"
        },
        "stars": {
          "anyOf": [
            {
              "minimum": 0,
              "type": "integer"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "GitHub stars",
          "title": "Stars"
        },
        "forks": {
          "anyOf": [
            {
              "minimum": 0,
              "type": "integer"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "GitHub forks",
          "title": "Forks"
        },
        "rank": {
          "anyOf": [
            {
              "$ref": "#/$defs/MSFRank"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Metasploit rank"
        },
        "command": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "CLI command to run the exploit (e.g., msfconsole command)",
          "title": "Command"
        },
        "labels": {
          "description": "Heuristic PoC quality labels (scanner, poc, writeup, \u2026)",
          "items": {
            "type": "string"
          },
          "title": "Labels",
          "type": "array"
        },
        "last_commit": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Last repository push time (ISO-8601), when known",
          "title": "Last Commit"
        },
        "trust_score": {
          "anyOf": [
            {
              "maximum": 1.0,
              "minimum": 0.0,
              "type": "number"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Heuristic trust score in [0.0, 1.0]",
          "title": "Trust Score"
        },
        "module_path": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Metasploit module path on disk, when known",
          "title": "Module Path"
        },
        "module_type": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Metasploit module type (exploit, auxiliary, \u2026)",
          "title": "Module Type"
        },
        "platform": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Metasploit platform target(s), when known",
          "title": "Platform"
        }
      },
      "required": [
        "source",
        "url"
      ],
      "title": "Exploit",
      "type": "object"
    },
    "ExploitSource": {
      "description": "Known sources for exploit code.",
      "enum": [
        "github",
        "exploitdb",
        "metasploit",
        "nuclei",
        "trickest",
        "nomi-sec",
        "other"
      ],
      "title": "ExploitSource",
      "type": "string"
    },
    "LabEnvironment": {
      "description": "A CTF lab or pre-built vulnerable Docker environment.\n\nAttributes:\n    platform: Hosting platform (HackTheBox, TryHackMe, Vulhub).\n    name: Room/machine/environment name.\n    url: Direct URL to access the lab.\n    setup_instructions: Step-by-step setup guide (for Vulhub).",
      "properties": {
        "platform": {
          "$ref": "#/$defs/LabPlatform",
          "description": "Lab platform"
        },
        "name": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Lab name",
          "title": "Name"
        },
        "url": {
          "description": "Lab URL",
          "title": "Url",
          "type": "string"
        },
        "setup_instructions": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "null"
            }
          ],
          "default": null,
          "description": "Setup instructions for local environments",
          "title": "Setup Instructions"
        }
      },
      "required": [
        "platform",
        "url"
      ],
      "title": "LabEnvironment",
      "type": "object"
    },
    "LabPlatform": {
      "description": "Platforms hosting CTF/lab environments.",
      "enum": [
        "hackthebox",
        "tryhackme",
        "vulhub",
        "other"
      ],
      "title": "LabPlatform",
      "type": "string"
    },
    "MSFRank": {
      "description": "Metasploit exploit reliability ranking.",
      "enum": [
        "excellent",
        "great",
        "good",
        "normal",
        "average",
        "low",
        "manual",
        "unknown"
      ],
      "title": "MSFRank",
      "type": "string"
    },
    "Severity": {
      "description": "CVSS severity levels.",
      "enum": [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN"
      ],
      "title": "Severity",
      "type": "string"
    }
  },
  "description": "A complete report entry for a single CVE.\n\nThis aggregates all discovered information about a CVE including\nexploit code, lab environments, and bug bounty reports.\n\nAttributes:\n    cve_info: Core CVE metadata and scoring.\n    exploits: List of discovered exploit code sources.\n    labs: List of available lab/CTF environments.\n    bb_reports: List of bug bounty write-ups.\n    generated_at: Timestamp when the report was generated.",
  "properties": {
    "cve_info": {
      "$ref": "#/$defs/CVEInfo",
      "description": "CVE information"
    },
    "exploits": {
      "description": "Discovered exploits",
      "items": {
        "$ref": "#/$defs/Exploit"
      },
      "title": "Exploits",
      "type": "array"
    },
    "labs": {
      "description": "Lab environments",
      "items": {
        "$ref": "#/$defs/LabEnvironment"
      },
      "title": "Labs",
      "type": "array"
    },
    "bb_reports": {
      "description": "Bug bounty reports",
      "items": {
        "$ref": "#/$defs/BugBountyReport"
      },
      "title": "Bb Reports",
      "type": "array"
    },
    "generated_at": {
      "description": "Report generation timestamp",
      "format": "date-time",
      "title": "Generated At",
      "type": "string"
    }
  },
  "required": [
    "cve_info"
  ],
  "title": "ReportEntry",
  "type": "object"
}
```

## `PackageVulnerability`

```json
{
  "$defs": {
    "Severity": {
      "description": "CVSS severity levels.",
      "enum": [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "UNKNOWN"
      ],
      "title": "Severity",
      "type": "string"
    }
  },
  "description": "A vulnerability affecting one *package* coordinate, as OSV files it.\n\nDistinct from :class:`CVEInfo`, which is keyed on a CPE product. The unit\nhere is a dependency \u2014 ``PyPI/django``, ``Maven/org.apache\u2026:log4j-core`` \u2014\nso this model carries the one thing a CPE record cannot: the releases that\nfix the issue.\n\n``fixed_versions`` is scoped to the queried package. One advisory covers\nevery package that ships the vulnerable code and their fix streams differ,\nso a version listed here is a real upgrade target for *this* package only.\nSeveral entries are normal rather than contradictory \u2014 a project backports\na fix to each maintained branch.\n\nAn empty ``fixed_versions`` means no fix is published for this package, not\nthat it is unaffected.\n\nAttributes:\n    id: OSV identifier (``GHSA-\u2026``, ``PYSEC-\u2026``, ``RUSTSEC-\u2026``, ``CVE-\u2026``).\n    aliases: Other identifiers the advisory is cross-referenced under.\n    cve_ids: CVE identifiers among ``id``/``aliases``; empty is common, as\n        many ecosystem advisories never receive one.\n    summary: One-line advisory title.\n    details: Full advisory prose, when the caller asked for it.\n    severity: Qualitative rating, derived from the CVSS vector when one is\n        scoreable and otherwise from the publisher's own label.\n    cvss_score: CVSS 3.x base score computed from ``cvss_vector``. ``None``\n        for a 4.0-only advisory, which pocmap does not score locally.\n    cvss_vector: The CVSS vector string as published.\n    fixed_versions: Releases fixing this issue *for this package*.\n    introduced_versions: Releases that introduced it.\n    epss: EPSS exploitation probability (0-100), when a CVE alias exists.\n    kev_status: Whether a CVE alias is in the CISA KEV catalog.\n    withdrawn: RFC3339 timestamp if the advisory was retracted.\n    published: Publication timestamp.\n    modified: Last-modified timestamp.\n    url: Canonical OSV page for the advisory.",
  "properties": {
    "id": {
      "description": "OSV advisory identifier",
      "title": "Id",
      "type": "string"
    },
    "aliases": {
      "description": "Cross-referenced identifiers",
      "items": {
        "type": "string"
      },
      "title": "Aliases",
      "type": "array"
    },
    "cve_ids": {
      "description": "CVE identifiers, if any",
      "items": {
        "type": "string"
      },
      "title": "Cve Ids",
      "type": "array"
    },
    "summary": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "One-line advisory title",
      "title": "Summary"
    },
    "details": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Full advisory text",
      "title": "Details"
    },
    "severity": {
      "$ref": "#/$defs/Severity",
      "default": "UNKNOWN",
      "description": "Qualitative severity"
    },
    "cvss_score": {
      "anyOf": [
        {
          "maximum": 10.0,
          "minimum": 0.0,
          "type": "number"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "CVSS 3.x base score, computed from the vector",
      "title": "Cvss Score"
    },
    "cvss_vector": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Published CVSS vector string",
      "title": "Cvss Vector"
    },
    "fixed_versions": {
      "description": "Releases that fix this issue for the queried package",
      "items": {
        "type": "string"
      },
      "title": "Fixed Versions",
      "type": "array"
    },
    "introduced_versions": {
      "description": "Releases that introduced this issue",
      "items": {
        "type": "string"
      },
      "title": "Introduced Versions",
      "type": "array"
    },
    "epss": {
      "anyOf": [
        {
          "maximum": 100.0,
          "minimum": 0.0,
          "type": "number"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "EPSS exploitation probability (0-100)",
      "title": "Epss"
    },
    "kev_status": {
      "default": false,
      "description": "Listed in the CISA KEV catalog",
      "title": "Kev Status",
      "type": "boolean"
    },
    "withdrawn": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Retraction timestamp, if withdrawn",
      "title": "Withdrawn"
    },
    "published": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Publication timestamp",
      "title": "Published"
    },
    "modified": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Last-modified timestamp",
      "title": "Modified"
    },
    "url": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "null"
        }
      ],
      "default": null,
      "description": "Canonical OSV advisory URL",
      "title": "Url"
    },
    "has_fix": {
      "description": "Whether at least one fixed release is published for this package.\n\nA ``computed_field`` rather than a plain property so it survives\n``model_dump()``. As a bare property it was absent from the CLI's\n``--format json`` and from the exported JSON Schema, while the MCP\nnormalizer re-added it by hand \u2014 so the two surfaces disagreed and a\nscript written against the documented shape raised ``KeyError``.",
      "readOnly": true,
      "title": "Has Fix",
      "type": "boolean"
    }
  },
  "required": [
    "id",
    "has_fix"
  ],
  "title": "PackageVulnerability",
  "type": "object"
}
```

