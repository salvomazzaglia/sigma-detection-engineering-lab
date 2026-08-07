"""The synthetic event record evaluated by the matcher.

Every event this laboratory handles is generated. There is no ingestion path
from real telemetry, and :attr:`SyntheticEvent.synthetic` is always true.

Field resolution order is documented and deliberate, because a matcher whose
lookup rules are implicit cannot be reasoned about:

1. exact key in :attr:`SyntheticEvent.fields`;
2. case-insensitive key in ``fields``;
3. a documented top-level alias (see :data:`TOP_LEVEL_ALIASES`).

Step 3 exists so fixtures can set ``host`` once instead of repeating
``Computer``, ``ComputerName``, and ``hostname`` in every event.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from sigma_detection_engineering_lab.errors import SdelError


class EventModelError(SdelError):
    """A synthetic event record is malformed."""


TOP_LEVEL_ALIASES: Final[dict[str, str]] = {
    "host": "host",
    "hostname": "host",
    "computer": "host",
    "computername": "host",
    "user": "user",
    "username": "user",
    "subjectusername": "user",
    "targetusername": "user",
    "timestamp": "timestamp",
    "@timestamp": "timestamp",
    "utctime": "timestamp",
    "eventid": "event_code",
    "event_id": "event_code",
    "eventcode": "event_code",
}
"""Lowercased Sigma field name to :class:`SyntheticEvent` attribute.

Documented in ``docs/matcher-subset.md``. Fixture ``fields`` entries always win,
so an event can override an alias by setting the field explicitly.
"""

SENTINEL_MISSING: Final[object] = object()
"""Returned by :meth:`SyntheticEvent.lookup` when a field is genuinely absent.

Distinguished from ``None``, which is a present-but-null value and matches a
Sigma ``null`` expression.
"""


def parse_timestamp(value: object, *, label: str = "timestamp") -> datetime:
    """Parse an ISO 8601 timestamp and normalise it to UTC.

    A naive timestamp is interpreted as UTC rather than local time, so fixtures
    behave identically regardless of the machine running them.

    Raises:
        EventModelError: if the value is not a parseable timestamp.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise EventModelError(f"{label}: not an ISO 8601 timestamp: {value!r}") from exc
    else:
        raise EventModelError(f"{label}: expected an ISO 8601 string, got {type(value).__name__}")

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    """Render a UTC timestamp in the canonical ``...Z`` form used by fixtures."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class SyntheticEvent:
    """One generated log record.

    Attributes:
        event_id: Stable identifier unique within its fixture file.
        timestamp: UTC occurrence time, used by the correlation engine.
        host: Synthetic hostname, e.g. ``SYNTHETIC-HOST-01``.
        user: Synthetic account name, if the record carries one.
        category: Sigma logsource category, e.g. ``process_creation``.
        product: Sigma logsource product, e.g. ``windows``.
        service: Sigma logsource service, e.g. ``security``.
        event_code: Platform event identifier, exposed as ``EventID``.
        channel: Windows channel or Unix log path the record came from.
        provider: Producing provider or subsystem name.
        platform: Operating-system family, e.g. ``windows``.
        scenario: One-line description of what the fixture is demonstrating.
        notes: Why the fixture is expected to match or not match.
        fields: The record body. Matching happens here first.
        labels: Free-form tags used to group fixtures.
        synthetic: Always true; retained so serialised events carry the marker.
    """

    event_id: str
    timestamp: datetime
    host: str = "SYNTHETIC-HOST-01"
    user: str | None = None
    category: str | None = None
    product: str | None = None
    service: str | None = None
    event_code: str | None = None
    channel: str | None = None
    provider: str | None = None
    platform: str | None = None
    scenario: str = ""
    notes: str = ""
    fields: Mapping[str, Any] = field(default_factory=dict)
    labels: tuple[str, ...] = ()
    synthetic: bool = True

    def __post_init__(self) -> None:
        if not self.synthetic:
            raise EventModelError(
                f"event {self.event_id!r}: this laboratory only handles synthetic events"
            )

    @property
    def logsource_label(self) -> str:
        """Render the logsource triple for display, omitting absent parts."""
        parts = [part for part in (self.product, self.category, self.service) if part]
        return "/".join(parts) if parts else "unspecified"

    def lookup(self, name: str) -> Any:
        """Resolve a Sigma field name against this event.

        Returns:
            The field value, or :data:`SENTINEL_MISSING` when the field is absent.
            A present field holding ``None`` returns ``None``, which is different
            from absent.
        """
        if name in self.fields:
            return self.fields[name]

        lowered = name.lower()
        for key, value in self.fields.items():
            if isinstance(key, str) and key.lower() == lowered:
                return value

        attribute = TOP_LEVEL_ALIASES.get(lowered)
        if attribute is not None:
            value = getattr(self, attribute, SENTINEL_MISSING)
            if value is SENTINEL_MISSING or value is None:
                return SENTINEL_MISSING
            return value
        return SENTINEL_MISSING

    def has_field(self, name: str) -> bool:
        """Return whether the field resolves to anything at all."""
        return self.lookup(name) is not SENTINEL_MISSING

    def to_mapping(self) -> dict[str, Any]:
        """Serialise to the JSONL fixture representation."""
        payload: dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp_utc": format_timestamp(self.timestamp),
            "host": self.host,
            "synthetic": True,
        }
        if self.user is not None:
            payload["user"] = self.user
        logsource = {
            key: value
            for key, value in (
                ("category", self.category),
                ("product", self.product),
                ("service", self.service),
            )
            if value is not None
        }
        if logsource:
            payload["logsource"] = logsource
        for key, value in (
            ("channel", self.channel),
            ("provider", self.provider),
            ("platform", self.platform),
        ):
            if value is not None:
                payload[key] = value
        if self.event_code is not None:
            payload["event_code"] = self.event_code
        payload["fields"] = dict(self.fields)
        for key, value in (("scenario", self.scenario), ("notes", self.notes)):
            if value:
                payload[key] = value
        if self.labels:
            payload["labels"] = list(self.labels)
        return payload

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, label: str = "event") -> SyntheticEvent:
        """Build an event from a decoded JSONL record.

        Raises:
            EventModelError: if required keys are missing or badly typed.
        """
        if not isinstance(data, Mapping):
            raise EventModelError(f"{label}: expected an object, got {type(data).__name__}")

        event_id = data.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise EventModelError(f"{label}: 'event_id' must be a non-empty string")

        raw_timestamp = data.get("timestamp_utc", data.get("timestamp"))
        if raw_timestamp is None:
            raise EventModelError(
                f"{label}: 'timestamp_utc' is required; every synthetic event is timestamped "
                "in UTC so correlation results do not depend on the machine running them"
            )
        timestamp = parse_timestamp(raw_timestamp, label=f"{label}.timestamp_utc")

        # The logsource triple may be written inline or nested, matching how the
        # Sigma rule that consumes the event declares it.
        nested = data.get("logsource", {})
        if not isinstance(nested, Mapping):
            raise EventModelError(f"{label}: 'logsource' must be an object")

        def logsource_part(key: str) -> object:
            return data.get(key, nested.get(key))

        raw_fields = data.get("fields", {})
        if not isinstance(raw_fields, Mapping):
            raise EventModelError(f"{label}: 'fields' must be an object")
        for key in raw_fields:
            if not isinstance(key, str):
                raise EventModelError(f"{label}: field names must be strings, got {key!r}")

        labels_raw = data.get("labels", ())
        if isinstance(labels_raw, str):
            raise EventModelError(f"{label}: 'labels' must be a list, not a string")
        labels = tuple(str(item) for item in labels_raw) if labels_raw else ()

        synthetic = data.get("synthetic", True)
        if synthetic is not True:
            raise EventModelError(
                f"{label}: 'synthetic' must be true; non-synthetic records are refused"
            )

        fields = dict(raw_fields)
        event_code = data.get("event_code")
        if event_code is None:
            for key in ("EventID", "EventCode"):
                if key in fields:
                    event_code = fields[key]
                    break

        return cls(
            event_id=event_id,
            timestamp=timestamp,
            host=str(data.get("host", "SYNTHETIC-HOST-01")),
            user=_optional_str(data.get("user"), f"{label}.user"),
            category=_optional_str(logsource_part("category"), f"{label}.category"),
            product=_optional_str(logsource_part("product"), f"{label}.product"),
            service=_optional_str(logsource_part("service"), f"{label}.service"),
            event_code=_optional_str(event_code, f"{label}.event_code"),
            channel=_optional_str(data.get("channel"), f"{label}.channel"),
            provider=_optional_str(data.get("provider"), f"{label}.provider"),
            platform=_optional_str(data.get("platform"), f"{label}.platform"),
            scenario=str(data.get("scenario", "") or ""),
            notes=str(data.get("notes", "") or ""),
            fields=fields,
            labels=labels,
            synthetic=True,
        )


def _optional_str(value: object, label: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int)):
        return str(value)
    raise EventModelError(f"{label}: expected a string, got {type(value).__name__}")


def matches_logsource(
    event: SyntheticEvent,
    category: str | None,
    product: str | None,
    service: str | None,
) -> bool:
    """Return whether an event satisfies a Sigma logsource selector.

    An unspecified selector component matches anything, mirroring the Sigma
    specification. Comparison is case-insensitive.
    """

    def part_matches(required: str | None, actual: str | None) -> bool:
        if required is None:
            return True
        if actual is None:
            return False
        return required.strip().lower() == actual.strip().lower()

    return (
        part_matches(category, event.category)
        and part_matches(product, event.product)
        and part_matches(service, event.service)
    )


__all__ = [
    "SENTINEL_MISSING",
    "TOP_LEVEL_ALIASES",
    "EventModelError",
    "SyntheticEvent",
    "format_timestamp",
    "matches_logsource",
    "parse_timestamp",
]
