from siteadmin.events import detect


def test_detects_service_and_domain_transitions():
    current = {
        "memory": {"used_percent": 50},
        "disks": [],
        "ports": [],
        "services": {"nginx": "inactive"},
        "certs": [{"domain": "example.com", "days_left": 10}],
        "reachability": [{"domain": "example.com", "reachable": False}],
    }
    previous = {
        "memory": {"used_percent": 50},
        "disks": [],
        "ports": [],
        "services": {"nginx": "active"},
        "certs": [{"domain": "example.com", "days_left": 20}],
        "reachability": [{"domain": "example.com", "reachable": True}],
    }

    types = {event["type"] for event in detect(current, previous)}

    assert types == {"service_down", "certificate_expiry_soon", "domain_unreachable"}


def test_does_not_repeat_unchanged_alerts():
    state = {
        "memory": {"used_percent": 50},
        "disks": [],
        "ports": [],
        "services": {"nginx": "inactive"},
        "certs": [{"domain": "example.com", "days_left": 10}],
        "reachability": [{"domain": "example.com", "reachable": False}],
    }

    assert detect(state, state) == []
