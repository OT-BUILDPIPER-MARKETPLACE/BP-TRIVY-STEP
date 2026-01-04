#!/bin/bash

source /opt/buildpiper/shell-functions/functions.sh
source /opt/buildpiper/shell-functions/mi-functions.sh
source /opt/buildpiper/shell-functions/log-functions.sh
source /opt/buildpiper/shell-functions/str-functions.sh
source /opt/buildpiper/shell-functions/file-functions.sh
source /opt/buildpiper/shell-functions/aws-functions.sh
source /opt/buildpiper/shell-functions/getDataFile.sh

login_all_registries() {
  local REGISTRY_FILE="/bp/data/environment_build"

  if [[ -z "$REGISTRY_FILE" || ! -f "$REGISTRY_FILE" ]]; then
    logErrorMessage "Registry file not found"
    return 1
  fi

  if [[ -z "$FERNET_KEY" ]]; then
    logErrorMessage "FERNET_KEY environment variable not set"
    return 1
  fi

  jq -c '.registry[]' "$REGISTRY_FILE" | while read -r reg; do
    NAME=$(echo "$reg" | jq -r '.name')
    URL=$(echo "$reg" | jq -r '.url')
    ENC_USER=$(echo "$reg" | jq -r '.username')
    ENC_PASS=$(echo "$reg" | jq -r '.password')

    logInfoMessage "Logging into $NAME -> $URL"

    USERNAME=$(python3 - <<EOF
from cryptography.fernet import Fernet
import os
print(Fernet(os.environ["FERNET_KEY"].encode()).decrypt(b"$ENC_USER").decode())
EOF
)

    PASSWORD=$(python3 - <<EOF
from cryptography.fernet import Fernet
import os
print(Fernet(os.environ["FERNET_KEY"].encode()).decrypt(b"$ENC_PASS").decode())
EOF
)

    echo "$PASSWORD" | docker login "$URL" \
      --username "$USERNAME" \
      --password-stdin

    if [[ $? -ne 0 ]]; then
      logErrorMessage "Login failed for $NAME"
      return 1
    fi

    logInfoMessage "Login successful for $NAME"
    logInfoMessage "--------------------------------"
  done
}