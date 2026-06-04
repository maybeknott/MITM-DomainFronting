#!/usr/bin/env python3
"""Attach JA3 pool metadata and uTLS fingerprints to generated Xray profiles."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPACK_TAG_PREFIX = "tls-repack"


def load_pool(pool_path: Path) -> Dict[str, Any]:
    data = json.loads(pool_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{pool_path}: pool must be a JSON object")
    pool_id = str(data.get("pool_id") or "").strip()
    templates = data.get("templates")
    if not pool_id:
        raise ValueError(f"{pool_path}: missing pool_id")
    if not isinstance(templates, list) or not templates:
        raise ValueError(f"{pool_path}: templates must be a non-empty list")
    return data


def load_profile_pool_map(map_path: Path) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyYAML required for ja3-profile-pools.yml") from exc
    data = yaml.safe_load(map_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{map_path}: mapping must be a YAML object")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict):
        raise ValueError(f"{map_path}: missing profiles mapping")
    return data


def select_template(pool: Dict[str, Any], template_index: int) -> Dict[str, Any]:
    templates: List[Any] = pool["templates"]
    index = template_index % len(templates)
    template = templates[index]
    if not isinstance(template, dict):
        raise ValueError(f"templates[{index}] must be an object")
    template_id = str(template.get("id") or f"index-{index}")
    utls = str(template.get("utls_fingerprint") or "chrome").strip() or "chrome"
    ja3_hash = str(template.get("ja3_hash_md5") or "").strip().lower()
    ja3_string = str(template.get("ja3_string") or "")
    return {
        "template_id": template_id,
        "template_index": index,
        "utls_fingerprint": utls,
        "ja3_hash_md5": ja3_hash,
        "ja3_string": ja3_string,
    }


def attach_ja3_pool_to_config(
    config: Dict[str, Any],
    *,
    profile_name: str,
    pool_path: Path,
    template_index: int,
    root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Mutate config in place; return summary of attachments."""
    pool = load_pool(pool_path)
    template = select_template(pool, template_index)
    pool_id = str(pool["pool_id"])

    mitm = config.setdefault("mitm", {})
    if not isinstance(mitm, dict):
        raise ValueError("config.mitm must be an object when present")
    mitm["ja3_pool_id"] = pool_id
    mitm["ja3_template_id"] = template["template_id"]
    mitm["ja3_template_index"] = template["template_index"]
    mitm["ja3_hash_md5"] = template["ja3_hash_md5"]
    mitm["operating_profile"] = profile_name
    if root is not None:
        try:
            mitm["ja3_pool_file"] = str(pool_path.resolve().relative_to(root.resolve())).replace("\\", "/")
        except ValueError:
            mitm["ja3_pool_file"] = str(pool_path).replace("\\", "/")
    else:
        mitm["ja3_pool_file"] = str(pool_path).replace("\\", "/")

    attached: List[str] = []
    for outbound in config.get("outbounds", []):
        if not isinstance(outbound, dict):
            continue
        tag = str(outbound.get("tag") or "")
        if not tag.startswith(REPACK_TAG_PREFIX):
            continue
        stream = outbound.setdefault("streamSettings", {})
        if not isinstance(stream, dict):
            continue
        tls = stream.setdefault("tlsSettings", {})
        if not isinstance(tls, dict):
            continue
        tls["fingerprint"] = template["utls_fingerprint"]
        outbound["mitmMeta"] = {
            "ja3_pool_id": pool_id,
            "ja3_template_id": template["template_id"],
            "ja3_template_index": template["template_index"],
            "ja3_hash_md5": template["ja3_hash_md5"],
            "operating_profile": profile_name,
        }
        attached.append(tag)

    return {
        "profile": profile_name,
        "pool_id": pool_id,
        "template_id": template["template_id"],
        "fingerprint": template["utls_fingerprint"],
        "repack_outbounds": attached,
    }


def attach_for_operating_profile(
    config: Dict[str, Any],
    profile_name: str,
    root: Path,
    *,
    map_path: Optional[Path] = None,
) -> Dict[str, Any]:
    root = root.resolve()
    mapping_path = map_path or (root / "config-src" / "ja3-profile-pools.yml")
    mapping = load_profile_pool_map(mapping_path)
    profiles = mapping["profiles"]
    if profile_name not in profiles:
        raise KeyError(f"no JA3 pool mapping for profile {profile_name!r}")
    profile_entry = profiles[profile_name]
    if not isinstance(profile_entry, dict):
        raise ValueError(f"profiles.{profile_name} must be an object")
    template_index = int(profile_entry.get("template_index", 0))
    pool_rel = str(mapping.get("default_pool_file") or "").strip()
    if not pool_rel:
        raise ValueError(f"{mapping_path}: missing default_pool_file")
    pool_path = root / pool_rel
    return attach_ja3_pool_to_config(
        config,
        profile_name=profile_name,
        pool_path=pool_path,
        template_index=template_index,
        root=root,
    )


def validate_all_profiles_have_pool_metadata(config_dir: Path, profiles: Tuple[str, ...]) -> List[str]:
    errors: List[str] = []
    for profile in profiles:
        path = config_dir / f"MITM-DomainFronting.{profile}.json"
        if not path.exists():
            errors.append(f"missing profile config: {path}")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        mitm = data.get("mitm") if isinstance(data.get("mitm"), dict) else {}
        pool_id = str(mitm.get("ja3_pool_id") or "").strip()
        if not pool_id:
            errors.append(f"{path}: mitm.ja3_pool_id not set (run generate_profiles with JA3 attach)")
        repack = [
            ob
            for ob in data.get("outbounds", [])
            if isinstance(ob, dict) and str(ob.get("tag", "")).startswith(REPACK_TAG_PREFIX)
        ]
        for outbound in repack:
            meta = outbound.get("mitmMeta")
            if not isinstance(meta, dict) or str(meta.get("ja3_pool_id") or "") != pool_id:
                errors.append(f"{path}: outbound {outbound.get('tag')} missing matching mitmMeta.ja3_pool_id")
    return errors
