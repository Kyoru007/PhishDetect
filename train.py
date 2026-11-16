"""Compatibility entry point for domain-grouped training."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from phishdetect.training import main
if __name__ == '__main__':
    main()
