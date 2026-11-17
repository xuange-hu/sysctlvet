"""sysctlvet — zero-dependency kernel parameter (sysctl) auditor.

Parses ``/etc/sysctl.conf`` and ``sysctl.d`` drop-ins into one normalized
assignment model, resolves which line actually wins with the ``sysctl
--system`` precedence order, then reasons in three passes:

* ``settings``  — the value of one effective setting (redirects, ASLR, BPF)
* ``combos``    — dangerous combinations (KASLR-defeat trifecta, dump chains)
* ``relations`` — the gaps between files (dead settings, reverted hardening)
"""

from .__about__ import __version__

__all__ = ["__version__"]
