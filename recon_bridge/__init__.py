"""recon-bridge: an authorization-aware recon toolkit exposed over MCP.

Every capability lives behind a safety backbone (scope enforcement, audit
logging, rate limiting) so the tools can only ever touch targets you are
explicitly authorized to test.
"""

__version__ = "0.2.0"
