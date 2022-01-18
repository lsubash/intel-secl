#!/bin/bash

COMPONENT_NAME=workload-agent
BINARY_NAME=wlagent
WORKLOAD_AGENT_HOME=/opt/workload-agent
CONFIG_PATH=/etc/$COMPONENT_NAME

# Do nothing for container deployment, container deployment comes with grpc service as default in v4.1.0 container image
if [ -f "/.container-env" ]; then
  exit 0
fi

echo "Starting $COMPONENT_NAME config upgrade to v5.0.0"
# Update config file
./config-upgrade ./config/v5.0.0_config.tmpl $1/config.yml $CONFIG_PATH/config.yml
if [ $? -ne 0 ]; then
  echo "Failed to update config to v5.0.0"
  exit 1
fi


echo "Completed $COMPONENT_NAME config upgrade to v5.0.0"