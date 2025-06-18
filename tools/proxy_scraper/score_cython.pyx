# cython: language_level=3

WEIGHTS = {"ip_rep": 179, "tls_reach": 152}
CRITICAL_KEYS = ("ip_rep", "tls_reach")
OVERALL_MIN = 250
CRITICAL_MIN = 120

cpdef tuple score_single_proxy(dict data):
    """Return ``(total, critical)`` score using two metrics."""
    cdef int total = 0
    cdef int critical = 0
    cdef object val

    val = data.get("ip_rep")
    if val is not None:
        total += int(val * WEIGHTS["ip_rep"])
        critical += int(val * WEIGHTS["ip_rep"])

    val = data.get("tls_reach")
    if val is not None:
        total += int(val * WEIGHTS["tls_reach"])
        critical += int(val * WEIGHTS["tls_reach"])

    return total, critical
