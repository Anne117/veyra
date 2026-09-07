#!/bin/bash
# Local build
python -m build
pytest tests/
