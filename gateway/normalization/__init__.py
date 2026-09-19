"""Detection-only normalization with a reversible map to the original text.

This package exists to resolve a contradiction the earlier design could not:
detection needs normalized text, and the customer's bytes must reach the
provider unchanged. Previously we chose the first and forwarded the normalized
text (SI-01 at the cost of SI-17). Now we build a *view* for detection, map the
spans back, and replace only validated source spans in the original.

See docs/adr/0015-normalization-order-and-offset-mapping.md.
"""

from gateway.normalization.confusables import CONFUSABLE_MAP, fold_confusables
from gateway.normalization.screening import (
    ScreeningResult,
    SuspiciousEncodingError,
    screen_text,
)
from gateway.normalization.view import (
    DetectionView,
    SpanMappingError,
    build_detection_view,
)

__all__ = [
    "CONFUSABLE_MAP",
    "DetectionView",
    "ScreeningResult",
    "SpanMappingError",
    "SuspiciousEncodingError",
    "build_detection_view",
    "fold_confusables",
    "screen_text",
]
