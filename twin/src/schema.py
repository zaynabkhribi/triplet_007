"""Data contract of the Twin: what each device accepts, and how values are written on the wire.

Everything a partner layer can send is checked here, and a rejection says why."""
from settings import log  # noqa: F401


ALLOWED_COMMANDS = {
    "light": {"phase": ["red", "yellow", "green"], "cycleTime": None, "mode": ["auto", "manual"]},
    "sign": {"message": None, "roadClosed": [True, False]},
    "alarm": {"alarmState": ["on", "off"]},
    "dispatch": {"status": ["idle", "dispatched", "onScene"], "unitsDispatched": None, "incidentId": None},
    "task": {"taskStatus": ["none", "created", "inProgress", "done"], "location": None},
}
INT_FIELDS = {"cycleTime", "unitsDispatched"}

INITIAL_STATE = {
    "light": {"phase": "red", "cycleTime": 60, "mode": "auto"},
    "sign": {"message": "", "roadClosed": False},
    "alarm": {"alarmState": "off"},
    "dispatch": {"status": "idle", "unitsDispatched": 0, "incidentId": ""},
    "task": {"taskStatus": "none", "location": ""},
    "bin": {"fill": 5.0},
}
ACTUATORS = set(ALLOWED_COMMANDS)
SENSOR_KINDS = {"traffic", "building", "camera", "bin", "ops"}
KNOWN_KINDS = ACTUATORS | SENSOR_KINDS

# Broker/platform metadata: never treated as actuator commands or reported as unknown.
BROKER_ATTRS = {
    "id", "type", "timestamp", "TimeInstant", "dateModified", "dateCreated",
    "latitude", "longitude", "model",
}

# Alert limits and effect durations. config.json ("thresholds", "effects") overrides them.
DEFAULT_THRESHOLDS = {
    "traffic_warning": 50, "traffic_critical": 75,
    "smoke_warning": 10, "smoke_critical": 100,
    "temperature_warning": 38, "temperature_critical": 60,
    "fill_warning": 80, "fill_critical": 95,
    "offline_after_ticks": 3,
}
DEFAULT_EFFECTS = {"fire_suppress_ticks": 6, "cleaning_ticks": 3}


_ORION_BAD = str.maketrans({";": ",", "(": "[", ")": "]", "=": ":",
                            "<": "", ">": "", '"': "", "'": ""})


def clean_text(text):
    """Orion rejects < > " ' = ; ( ) in string values: replace or strip them."""
    return str(text).translate(_ORION_BAD)


def to_attr(value):
    """Python value -> NGSI attribute {type, value}."""
    if isinstance(value, bool):
        return {"type": "string", "value": "true" if value else "false"}
    if isinstance(value, (int, float)):
        return {"type": "float", "value": value}
    return {"type": "string", "value": clean_text(value)}


def from_attr(key, raw):
    """NGSI value read back from the broker -> Python value (None if empty)."""
    if raw in ("", None):
        return None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str) and raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    if key in INT_FIELDS:
        try:
            return int(float(raw))
        except (TypeError, ValueError):
            return raw
    return raw


def validate_command(kind, payload):
    """Check a command written on an actuator. Returns None when valid, otherwise a sentence
    that says what is wrong and what is allowed."""
    rules = ALLOWED_COMMANDS.get(kind)
    if rules is None:
        return f"not an actuator (kind {kind})"
    if not isinstance(payload, dict) or not payload:
        return "empty command"
    for key, value in payload.items():
        if key not in rules:
            return f"unknown attribute {key!r}; allowed: {', '.join(rules)}"
        allowed = rules[key]
        if allowed is not None and value not in allowed:
            return f"bad value {value!r} for {key}; allowed: {', '.join(str(a) for a in allowed)}"
        if key in INT_FIELDS:
            try:
                int(float(value))
            except (TypeError, ValueError):
                return f"bad value {value!r} for {key}; a whole number is expected"
    return None
