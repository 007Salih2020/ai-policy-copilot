#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN="${PYTHON_BIN:-/opt/homebrew/bin/python3.11}"
STREAMLIT_PORT="${STREAMLIT_PORT:-8503}"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  if command -v python3.11 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3.11)"
  else
    echo "Python 3.11 was not found. Set PYTHON_BIN to a valid Python 3.11 interpreter." >&2
    exit 1
  fi
fi

if [[ ! -d "venv" ]]; then
  echo "Creating virtual environment with ${PYTHON_BIN}..."
  "${PYTHON_BIN}" -m venv venv
fi

if [[ ! -x "venv/bin/streamlit" ]]; then
  echo "Installing project dependencies with UI extras..."
  venv/bin/pip install -e '.[dev,ui]'
fi

echo "Cleaning Python caches..."
find src tests -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
find . -maxdepth 1 -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true
find src tests -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null || true
rm -rf .pytest_cache .mypy_cache .ruff_cache .streamlit/cache 2>/dev/null || true

echo "Cleaning Streamlit caches..."
venv/bin/streamlit cache clear >/dev/null 2>&1 || true
rm -rf "${HOME}/.streamlit/cache" "${HOME}/.cache/streamlit" 2>/dev/null || true

echo "Starting Streamlit on http://localhost:${STREAMLIT_PORT}"
exec venv/bin/streamlit run ui.py \
  --server.address 0.0.0.0 \
  --server.port "${STREAMLIT_PORT}" \
  --server.headless true
