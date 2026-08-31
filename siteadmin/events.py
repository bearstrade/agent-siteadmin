"""Детекция событий по смене агрегированного состояния."""


def detect(current: dict, previous: dict | None = None) -> list[dict]:
    previous = previous or {}
    events = []
    memory = current.get("memory", {})
    if (memory.get("used_percent") or 0) >= 95:
        events.append({"type": "memory_critical", "severity": "critical", "memory_used_percent": memory.get("used_percent")})
    elif (memory.get("used_percent") or 0) >= 85:
        events.append({"type": "memory_high", "severity": "high", "memory_used_percent": memory.get("used_percent")})
    for disk in current.get("disks", []):
        if disk.get("used_percent", 0) >= 95:
            events.append({"type": "disk_critical", "severity": "critical", "mount": disk.get("mount"), "used_percent": disk.get("used_percent")})
        elif disk.get("used_percent", 0) >= 85:
            events.append({"type": "disk_high", "severity": "high", "mount": disk.get("mount"), "used_percent": disk.get("used_percent")})
    added = sorted(set(current.get("ports", [])) - set(previous.get("ports", [])))
    if added:
        events.append({"type": "new_listener", "severity": "medium", "ports": added})
    for name, status in current.get("services", {}).items():
        old_status = (previous.get("services") or {}).get(name)
        if status == "active" and old_status and old_status != "active":
            events.append({"type": "service_recovered", "severity": "info", "service": name})
        elif status != "active" and old_status == "active":
            events.append({"type": "service_down", "severity": "high", "service": name, "status": status})
    old_certs = {item.get("domain"): item.get("days_left") for item in previous.get("certs", [])}
    for item in current.get("certs", []):
        days_left = item.get("days_left")
        if days_left is not None and days_left < 14 and (old_certs.get(item.get("domain")) is None or old_certs.get(item.get("domain")) >= 14):
            events.append({"type": "certificate_expiry_soon", "severity": "high", "domain": item.get("domain"), "days_left": days_left})
    old_reachability = {item.get("domain"): item.get("reachable") for item in previous.get("reachability", [])}
    for item in current.get("reachability", []):
        domain = item.get("domain")
        reachable = item.get("reachable")
        if reachable is False and old_reachability.get(domain) is not False:
            events.append({"type": "domain_unreachable", "severity": "high", "domain": domain})
        elif reachable is True and old_reachability.get(domain) is False:
            events.append({"type": "domain_recovered", "severity": "info", "domain": domain})
    return events
