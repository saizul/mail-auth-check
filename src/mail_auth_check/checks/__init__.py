"""The individual checks. Each takes a ``CheckContext`` and returns a ``CheckResult``."""

from .base import RFC, CheckContext, score_by_severity
from .bimi import check_bimi
from .dkim import check_dkim
from .dmarc import check_dmarc
from .mx import check_mx
from .senders import check_headers, check_reverse_dns, check_senders
from .spf import check_spf
from .transport import check_mta_sts, check_tlsrpt

__all__ = [
    "RFC",
    "CheckContext",
    "check_bimi",
    "check_dkim",
    "check_dmarc",
    "check_headers",
    "check_mta_sts",
    "check_mx",
    "check_reverse_dns",
    "check_senders",
    "check_spf",
    "check_tlsrpt",
    "score_by_severity",
]
