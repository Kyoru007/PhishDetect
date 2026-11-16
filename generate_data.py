"""Generate synthetic data with explicit provenance (compatibility command)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from phishdetect.dataset import build
from phishdetect.synthetic import legit, phishing

if __name__ == '__main__':
    build(Path('data'), limit=6000, offline=True)
