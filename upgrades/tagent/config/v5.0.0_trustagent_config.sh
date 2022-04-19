#!/bin/bash

SERVICE_NAME=tagent
COMPONENT_NAME=trustagent
CONFIG_PATH=/opt/$COMPONENT_NAME/configuration/
echo "Starting $COMPONENT_NAME config upgrade to v5.0.0"

# Update config file
./config-upgrade ./config/v5.0.0_config.tmpl $CONFIG_PATH/config.yml $1/config.yml
if [ $? -ne 0 ]; then
  echo "Failed to update config to v5.0.0"
  exit 1
fi

echo "Completed $COMPONENT_NAME config upgrade to v5.0.0"
