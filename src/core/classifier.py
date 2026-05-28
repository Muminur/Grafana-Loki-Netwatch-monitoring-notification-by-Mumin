"""Classification engine for BSCCL NetWatch.

Classifies a ``ParsedLog`` against the ordered rule list in
``src.data.classification_rules``.  First match wins.

Falls back to a default INFO/UNKNOWN result for unrecognised lines.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.data.classification_rules import _COMPILED_RULES

_log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from src.core.parser import ParsedLog


@dataclass(frozen=True)
class ClassificationResult:
    """Immutable classification outcome for a single syslog line.

    Attributes:
        rule_id:           Matched rule identifier, or ``"UNKNOWN"``.
        classification:    CRITICAL / WARNING / INFO / NOISE / USER_LOGIN.
        event_type:        Human-readable event type string.
        notify:            Whether a Discord/Telegram notification should fire.
        summary_template:  Template string for notification text.
    """

    rule_id: str
    classification: str
    event_type: str
    notify: bool
    summary_template: str


_DEFAULT_RESULT = ClassificationResult(
    rule_id="UNKNOWN",
    classification="INFO",
    event_type="Unknown Event",
    notify=False,
    summary_template="{device}: {raw}",
)


def classify(parsed_log: ParsedLog) -> ClassificationResult:
    """Classify a parsed syslog line against all rules (first match wins).

    Matches the ``raw`` field of *parsed_log* against each compiled pattern
    in ``_COMPILED_RULES`` in order.  Returns the first matching rule's
    classification wrapped in a :class:`ClassificationResult`.

    Returns a default INFO/UNKNOWN result for lines that match no rule.

    Args:
        parsed_log: A :class:`~src.core.parser.ParsedLog` produced by
                    :func:`~src.core.parser.parse_syslog`.

    Returns:
        A frozen :class:`ClassificationResult`.
    """
    try:
        raw = parsed_log.raw
    except (AttributeError, TypeError):
        _log.warning("classify() received invalid input: %r", parsed_log)
        return _DEFAULT_RESULT

    for compiled_pattern, rule in _COMPILED_RULES:
        if compiled_pattern.search(raw):
            return ClassificationResult(
                rule_id=rule.id,
                classification=rule.classification,
                event_type=rule.event_type,
                notify=rule.notify,
                summary_template=rule.summary_template,
            )

    _log.debug("No classification rule matched: %.200s", raw)
    return _DEFAULT_RESULT
