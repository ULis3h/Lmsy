# VulnSimilarityDetector

A vulnerability detection tool based on website similarity vectors.

## Features

- Website analysis and vector generation
- Vector similarity search against known vulnerable websites
- Automatic vulnerability detection based on similarity matching
- Vector database storage for known vulnerable websites

## Requirements

- Python 3.8+
- Required packages listed in requirements.txt

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
from vuln_detector import VulnDetector

detector = VulnDetector()
results = detector.analyze_url("https://example.com")
print(results.potential_vulnerabilities)
```