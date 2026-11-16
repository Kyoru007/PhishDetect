"""Compatibility imports for packaged lexical features."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from phishdetect.features import FEATURE_NAMES, extract_features, red_flags
__all__ = ['FEATURE_NAMES', 'extract_features', 'red_flags']
