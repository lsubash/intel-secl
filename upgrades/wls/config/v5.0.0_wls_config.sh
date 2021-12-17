#!/bin/bash

SERVICE_USERNAME=wls
COMPONENT_NAME=workload-service
CONFIG_PATH=/etc/$COMPONENT_NAME
PRODUCT_HOME=/opt/$SERVICE_USERNAME
ExecStart="\/usr\/bin\/wls\ run"
OLD_PRODUCT_HOME=/opt/$COMPONENT_NAME
echo "Starting $COMPONENT_NAME config upgrade to v5.0.0"

# Update config file
./config-upgrade ./config/v5.0.0_config.tmpl $1/config.yml $CONFIG_PATH/config.yml
if [ $? -ne 0 ]; then
  echo "Failed to update config to v5.0.0"
  exit 1
fi

# Update paths in the config file to the new path
sed -i 's/\/etc\/workload-service\//\/etc\/wls\//g' $CONFIG_PATH/config.yml

#update Execstart path in wls.service
#Skip this step for container deployment
if [ ! -f "/.container-env" ]; then
  sed -i "s/ExecStart=.*/ExecStart=${ExecStart}/g" $OLD_PRODUCT_HOME/$COMPONENT_NAME.service
fi