"""Azure Foundations 6.0.0 - Section 10: Miscellaneous (manual)."""

from __future__ import annotations

# Section 10 contains manual operational controls (resource locks etc.).
# We rely on the Runner default (status=MANUAL) to surface these to the user
# with the catalog audit text. This module exists for symmetry and so that
# autodiscovery imports a real submodule for section 10.
