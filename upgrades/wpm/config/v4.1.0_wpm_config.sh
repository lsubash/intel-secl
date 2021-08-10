#!/bin/bash

SERVICE_NAME=wpm
CONFIG_FILE="/etc/$SERVICE_NAME/config.yml"

echo "Starting $SERVICE_NAME config upgrade to v4.1.0"

# Add OCICRYPT_KEYPROVIDER_NAME setting to config.yml
grep -q 'ocicrypt-keyprovider-name' $CONFIG_FILE || echo 'ocicrypt-keyprovider-name: isecl' >>$CONFIG_FILE

echo "Completed $SERVICE_NAME config upgrade to v4.1.0"