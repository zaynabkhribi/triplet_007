"""Everything the Twin knows about how to talk to Orion (NGSI v2 through the Broker Filter).

No city logic here: change this file, or the "orion" block of config.json, to talk to another
broker. A device gets one OrionClient and only calls send() and fetch()."""
import json
import os
import sys
import time

import requests

from schema import to_attr
from settings import log

HINTS = {
    400: "the broker rejected the value (forbidden characters or wrong attribute)",
    401: "wrong K1/K2, or the id or type does not match the device in the IoT Directory",
    403: "this device is not allowed to do this",
    404: "unknown entity, or wrong base_url in config.json",
}


class OrionClient:
    def __init__(self, dev_id, dev_type, orion_conf, secret, secrets_dir):
        self.id = dev_id
        self.type = dev_type
        self.orion = orion_conf
        self.base = orion_conf["base_url"].rstrip("/")
        self.timeout = orion_conf.get("timeout", 10)
        self.verify = orion_conf.get("ca") or True
        self.k1 = secret.get("k1", "")
        self.k2 = secret.get("k2", "")
        self.cert = None          # optional TLS client certificate instead of K1/K2
        if secret.get("cert") and secret.get("key"):
            crt, key = (p if os.path.isabs(p) else os.path.join(secrets_dir, p)
                        for p in (secret["cert"], secret["key"]))
            for f in (crt, key):
                if not os.path.exists(f):
                    sys.exit(f"{dev_id}: file not found: {f}")
            self.cert = (crt, key)
        self.http = requests.Session()
        self.errors = 0

    def scrub(self, text):
        text = str(text)
        for secret in (self.k1, self.k2):
            if secret:
                text = text.replace(secret, "***")
        return text

    def _auth(self):
        if self.cert:   # certificate authentication: no keys in the URL
            return {"elementid": self.id, "type": self.type}
        return {"elementid": self.id, "type": self.type, "k1": self.k1, "k2": self.k2}

    def _fail(self, what, detail):
        self.errors += 1
        if self.errors <= 3 or self.errors % 20 == 0:
            log.error("%s_FAIL %s: %s", what, self.id, self.scrub(detail))

    def _request(self, method, url, **kw):
        """HTTP call with up to 3 attempts on network errors and 5xx answers
        (the platform sometimes answers 500 to the first burst of requests)."""
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify)
        kw.setdefault("cert", self.cert)
        last_exc = None
        for attempt in range(3):
            try:
                resp = self.http.request(method, url, **kw)
                if resp.status_code < 500:
                    return resp
                last_exc = None
            except requests.RequestException as exc:
                resp, last_exc = None, exc
            if attempt < 2:
                time.sleep(1 + attempt)
        if last_exc is not None:
            raise last_exc
        return resp

    def send(self, payload):
        """Push attributes to the broker. Returns True on success."""
        attrs = {k: to_attr(v) for k, v in payload.items()}
        try:
            if self.cert or self.orion.get("api", "v2") == "v1":   # v1 is the API documented for X509
                body = {
                    "contextElements": [{
                        "type": self.type, "isPattern": "false", "id": self.id,
                        "attributes": [dict(name=k, **a) for k, a in attrs.items()],
                    }],
                    "updateAction": "APPEND",
                }
                resp = self._request("POST", f"{self.base}/v1/updateContext",
                                     params=self._auth(), json=body)
            else:
                resp = self._request("PATCH", f"{self.base}/v2/entities/{self.id}/attrs",
                                     params=self._auth(), json=attrs)
        except requests.RequestException as exc:
            self._fail("SEND", f"{type(exc).__name__}: {exc}")
            return False
        if resp.status_code >= 300:
            hint = HINTS.get(resp.status_code, "")
            self._fail("SEND", f"HTTP {resp.status_code} {resp.text[:150]}" + (f" ({hint})" if hint else ""))
            return False
        self.errors = 0
        log.info("PUBLISH %s %s", self.id, json.dumps(payload))
        return True

    def fetch(self):
        """Read the entity from the broker (actuators: look for commands)."""
        try:
            resp = self._request("GET", f"{self.base}/v2/entities/{self.id}", params=self._auth())
        except requests.RequestException as exc:
            self._fail("POLL", f"{type(exc).__name__}: {exc}")
            return None
        if resp.status_code != 200:
            hint = HINTS.get(resp.status_code, "")
            self._fail("POLL", f"HTTP {resp.status_code} {resp.text[:150]}" + (f" ({hint})" if hint else ""))
            return None
        try:
            return resp.json()
        except ValueError:
            self._fail("POLL", "response is not JSON")
            return None
