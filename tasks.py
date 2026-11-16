"""Portable runner: python tasks.py data|train|test|serve|screenshots|report."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / 'src'))


def main() -> None:
    task = sys.argv[1] if len(sys.argv) > 1 else 'help'
    os.environ['PYTHONPATH'] = str(ROOT / 'src') + os.pathsep + str(ROOT)
    commands = {'data': ['data/build_dataset.py'], 'train': ['train.py'], 'test': ['-m', 'pytest', '-q'],
        'serve': ['-m', 'uvicorn', 'phishdetect.api:app', '--host', '127.0.0.1', '--port', '8000'],
        'screenshots': ['scripts/screenshots.py'], 'report': ['scripts/update_readme.py']}
    if task not in commands:
        print(__doc__)
        return
    result = subprocess.run([sys.executable, *commands[task], *sys.argv[2:]], check=False)
    if result.returncode == 0 and task == 'train':
        result = subprocess.run([sys.executable, 'scripts/update_readme.py'], check=False)
    sys.exit(result.returncode)


if __name__ == '__main__':
    main()
