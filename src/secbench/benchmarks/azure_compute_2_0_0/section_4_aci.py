"""Azure Compute 2.0.0 - Section 4: Azure Container Instances (mostly manual)."""

from __future__ import annotations

# Azure Container Instances has limited mgmt SDK coverage for the configuration
# bits CIS audits. We rely on the catalog-defaulted MANUAL status for these
# controls, surfaced with the audit text.
