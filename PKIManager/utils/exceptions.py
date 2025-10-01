class SecurityError(RuntimeError):
    """Raised when a fatal error occurs in security certificate management."""


class SecurityConfigurationError(SecurityError):
    """Raised for configuration problems detected by PKI managers or responses."""
