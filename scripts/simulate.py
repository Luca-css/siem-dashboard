"""Generate realistic security traffic against a running mini-SIEM, for demos.

Standard library only, so it runs anywhere Python 3.12 does:

    python scripts/simulate.py                        # continuous noise + attacks
    python scripts/simulate.py --once                 # each attack scenario once, then exit
    python scripts/simulate.py --url http://siem:8000 --interval 0.5

Background noise: normal office logons (4624), the occasional mistyped password
(4625), network logons and admin privilege assignments (4672) - none of which
should alert. Attack scenarios (picked at random every few seconds):

* rdp_brute_force    - burst of 4625s from one external IP        -> brute_force_by_ip
* ssh_brute_force    - sshd "Failed password" syslog lines           -> brute_force_by_ip
* off_hours_logon    - RDP logon at 03:xx Sao Paulo time             -> logon_off_hours
* privilege_abuse    - 4672 for a regular user account               -> privilege_use_non_admin
* new_local_admin    - 4732 adding an account to Administrators      -> new_local_admin

IPs come from the documentation ranges (RFC 5737), so nothing real is involved.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

HOSTS = ["SRV-AD01", "SRV-FILE01", "SRV-WEB01", "SRV-DB01", "WS-0142", "WS-0187"]
USERS = ["lucas.santos", "ana.lima", "joao.pereira", "marcos.oliveira", "carla.souza"]
ADMINS = ["Administrator", "adm.lucas", "SYSTEM"]
INTERNAL_IPS = [f"10.10.20.{n}" for n in range(10, 60)]
ATTACKER_IPS = ["203.0.113.66", "198.51.100.23", "192.0.2.199", "203.0.113.150"]
SPRAY_USERS = ["admin", "administrator", "root", "test", "backup", "sql", "oracle"]
LOCAL_TZ = ZoneInfo("America/Sao_Paulo")


def now() -> datetime:
    return datetime.now(UTC)


def win(event_id: int, when: datetime, host: str, **data: Any) -> dict[str, Any]:
    return {
        "EventID": event_id,
        "TimeCreated": when.isoformat(),
        "Computer": host,
        "EventData": data,
    }


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def _post(self, path: str, data: bytes, content_type: str) -> dict[str, Any]:
        req = urllib.request.Request(  # noqa: S310 - URL comes from the CLI user
            self.base_url + path,
            data=data,
            headers={"Content-Type": content_type},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                result: dict[str, Any] = json.load(resp)
        except urllib.error.HTTPError as exc:
            result = json.load(exc)
        for alert in result.get("alerts", []):
            print(f"  [ALERT] {alert['severity'].upper():8} {alert['title']}")
        return result

    def windows(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return self._post("/events", json.dumps(events).encode(), "application/json")

    def syslog(self, lines: list[str]) -> dict[str, Any]:
        return self._post("/events/syslog", "\n".join(lines).encode(), "text/plain")


# ── Background noise ───────────────────────────────────────────────────────────


def noise() -> list[dict[str, Any]]:
    t = now()
    host, user, ip = random.choice(HOSTS), random.choice(USERS), random.choice(INTERNAL_IPS)
    roll = random.random()
    if roll < 0.55:  # network logon (file shares etc.)
        return [win(4624, t, host, TargetUserName=user, IpAddress=ip, LogonType="3")]
    if roll < 0.75:  # interactive / RDP logon during the working day
        logon_type = random.choice(["2", "10"])
        return [win(4624, t, host, TargetUserName=user, IpAddress=ip, LogonType=logon_type)]
    if roll < 0.90:  # one mistyped password followed by success
        return [
            win(4625, t, host, TargetUserName=user, IpAddress=ip, LogonType="2"),
            win(
                4624,
                t + timedelta(seconds=4),
                host,
                TargetUserName=user,
                IpAddress=ip,
                LogonType="2",
            ),
        ]
    # admin logon -> 4672 for an admin account (expected, must NOT alert)
    return [win(4672, t, host, SubjectUserName=random.choice(ADMINS))]


# ── Attack scenarios ───────────────────────────────────────────────────────────


def rdp_brute_force(client: Client) -> None:
    ip, host, start = random.choice(ATTACKER_IPS), random.choice(HOSTS[:4]), now()
    print(f"> RDP brute force from {ip} against {host}")
    events = [
        win(
            4625,
            start + timedelta(seconds=i * random.uniform(1, 4)),
            host,
            TargetUserName=random.choice(SPRAY_USERS),
            IpAddress=ip,
            LogonType="10",
        )
        for i in range(random.randint(6, 12))
    ]
    client.windows(events)


def ssh_brute_force(client: Client) -> None:
    ip, start = random.choice(ATTACKER_IPS), now()
    print(f"> SSH brute force from {ip} against web01 (syslog)")
    lines = []
    for i in range(random.randint(6, 10)):
        t = (start + timedelta(seconds=i * 2)).isoformat(timespec="seconds")
        user = random.choice(SPRAY_USERS)
        lines.append(
            f"{t} web01 sshd[{4000 + i}]: Failed password for invalid user {user} "
            f"from {ip} port {random.randint(30000, 60000)} ssh2"
        )
    client.syslog(lines)


def off_hours_logon(client: Client) -> None:
    # Event time is what matters, not when we send it: 03:xx local time today.
    local = datetime.now(LOCAL_TZ).replace(hour=3, minute=random.randint(0, 59), second=0)
    user, host = random.choice(USERS), random.choice(HOSTS)
    print(f"> RDP logon by {user} on {host} at {local:%H:%M} (Sao Paulo)")
    client.windows(
        [
            win(
                4624,
                local,
                host,
                TargetUserName=user,
                IpAddress=random.choice(INTERNAL_IPS),
                LogonType="10",
            )
        ]
    )


def privilege_abuse(client: Client) -> None:
    user, host = random.choice(USERS), random.choice(HOSTS)
    print(f"> Special privileges assigned to regular user {user} on {host}")
    client.windows([win(4672, now(), host, SubjectUserName=user)])


def new_local_admin(client: Client) -> None:
    actor, host = random.choice(USERS), random.choice(HOSTS)
    print(f"> {actor} adds an account to Administrators on {host}")
    client.windows(
        [
            win(
                4732,
                now(),
                host,
                SubjectUserName=actor,
                TargetUserName="Administrators",
                MemberName="-",
                MemberSid=f"S-1-5-21-1004336348-1177238915-682003330-{random.randint(1100, 1999)}",
            )
        ]
    )


SCENARIOS: dict[str, Callable[[Client], None]] = {
    "rdp_brute_force": rdp_brute_force,
    "ssh_brute_force": ssh_brute_force,
    "off_hours_logon": off_hours_logon,
    "privilege_abuse": privilege_abuse,
    "new_local_admin": new_local_admin,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="mini-SIEM base URL")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between noise batches")
    parser.add_argument(
        "--attack-every", type=float, default=8.0, help="average seconds between attack scenarios"
    )
    parser.add_argument("--once", action="store_true", help="run every scenario once and exit")
    parser.add_argument("--seed", type=int, help="random seed for reproducible runs")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
    client = Client(args.url)

    try:
        if args.once:
            client.windows([e for _ in range(10) for e in noise()])
            for scenario in SCENARIOS.values():
                scenario(client)
            return 0

        print(f"Sending traffic to {args.url} (Ctrl+C to stop)")
        next_attack = time.monotonic() + args.attack_every
        while True:
            client.windows(noise())
            if time.monotonic() >= next_attack:
                random.choice(list(SCENARIOS.values()))(client)
                next_attack = time.monotonic() + random.uniform(0.5, 1.5) * args.attack_every
            time.sleep(args.interval)
    except urllib.error.URLError as exc:
        print(f"Cannot reach {args.url}: {exc.reason}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
