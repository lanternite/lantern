from urllib.parse import urlsplit


HUB_LABELS = {
    "academictorrents": "Academic Torrents",
    "huggingface": "Hugging Face",
    "modelscope": "ModelScope",
    "modelscope_ai": "ModelScope 🇨🇳",
    "modelscope_cn": "ModelScope 🇸🇬",
}


def normalize_matches_payload(payload, artwork=None):
    out = {}
    for i, item in enumerate(payload.get("matches", [])):
        m = dict(item)
        m["confidence"] = round((256 - int(m.get("distance", 256))) / 256 * 100)
        hub = m.get("hub") or ""
        m["site"] = HUB_LABELS.get(hub, hub.replace("_", " ").title() or "Unknown source")
        m["dataset_name"] = m.get("dataset") or "Unknown dataset"
        candidate_url = m.get("source_url") or m.get("dataset_card")
        try:
            parsed_url = urlsplit(candidate_url) if candidate_url else None
            m["url"] = candidate_url if parsed_url and parsed_url.scheme in {"http", "https"} else None
        except (TypeError, ValueError):
            m["url"] = None
        m["artwork_id"] = artwork.id if artwork else None
        m["artwork_filename"] = artwork.filename if artwork else None
        m["locations"] = [{"path": m.get("path"), "url": m["url"]}]
        key = (m["artwork_id"], hub, m.get("dataset"), m.get("content_fingerprint") or f"no-fp-{i}")
        old = out.get(key)
        if not old:
            out[key] = m
        else:
            old["locations"] += m["locations"]
            if m["confidence"] > old["confidence"]:
                m["locations"] = old["locations"]
                out[key] = m

    for m in out.values():
        m["location_count"] = len(m["locations"])
    return list(out.values())
