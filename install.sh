#!/bin/bash
set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_PATH="$REPO_ROOT/.git/hooks/pre-commit"

cat > "$HOOK_PATH" << 'HOOK'
#!/bin/bash
python3 "$(git rev-parse --show-toplevel)/detector.py"
HOOK

chmod +x "$HOOK_PATH"

echo "Pre-commit hook successfully installed at $HOOK_PATH"
echo "Every commit will now be automatically scanned for secrets."
