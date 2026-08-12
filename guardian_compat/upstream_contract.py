from __future__ import annotations


def claim_template(component:str, version:str):
    return {
        "component":component,"version":version,
        "local_status":"EXTRACTED",
        "upstream_status":"UNVERIFIED",
        "required_sources":["official documentation","official repository release notes"],
        "rule":"Do not declare COMPATIBLE/INCOMPATIBLE from local version extraction alone."
    }
