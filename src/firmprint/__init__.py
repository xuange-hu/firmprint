"""firmprint — evidence-backed firmware fingerprinting for Cortex-M images.

Read-only, fully offline, zero required dependencies.  Optional `capstone`
upgrade turns address carving into register-level access analysis.
"""
from .analyze import VERSION, analyze, to_markdown
from .container import Image, Segment, load
from .evidence import Evidence, Finding, validate

__all__ = ["VERSION", "analyze", "to_markdown", "load", "Image", "Segment",
           "Finding", "Evidence", "validate"]
__version__ = VERSION
