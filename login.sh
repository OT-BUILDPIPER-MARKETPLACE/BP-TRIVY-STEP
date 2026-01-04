#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

login_all_registries() {
  local JSON_FILE="/bp/data/environment_build"

  [[ -f "$JSON_FILE" ]] || { logErrorMessage "JSON file not found"; return 1; }
  [[ -n "$FERNET_KEY" ]] || { logErrorMessage "FERNET_KEY not set"; return 1; }

  # Normalize registry → always array
  jq -c '
    if (.registry | type) == "array" then
      .registry[]
    else
      .registry
    end
  ' "$JSON_FILE" | while read -r reg; do

    NAME=$(jq -r '.name // empty' <<<"$reg")
    URL=$(jq -r '.url // empty' <<<"$reg")
    ENC_USER=$(jq -r '.username // empty' <<<"$reg")
    ENC_PASS=$(jq -r '.password // empty' <<<"$reg")

    if [[ -z "$NAME" || -z "$URL" ]]; then
      logErrorMessage "Invalid registry entry, skipping"
      continue
    fi

    USERNAME=$(python3 - <<PY
from cryptography.fernet import Fernet
import os
print(Fernet(os.environ["FERNET_KEY"].encode()).decrypt(b"$ENC_USER").decode())
PY
) || { logErrorMessage "Username decrypt failed for $NAME"; return 1; }

    PASSWORD=$(python3 - <<PY
from cryptography.fernet import Fernet
import os
print(Fernet(os.environ["FERNET_KEY"].encode()).decrypt(b"$ENC_PASS").decode())
PY
) || { logErrorMessage "Password decrypt failed for $NAME"; return 1; }

    logInfoMessage "[INFO] Logging into registry: $NAME"
    echo "[INFO] URL: $URL"

    echo "$PASSWORD" | docker login "$URL" \
      --username "$USERNAME" \
      --password-stdin || {
        echo "Docker login failed for $NAME"
        return 1
      }

    logInfoMessage "Login successful: $NAME"
    logInfoMessage "----------------------------------"
  done
}
