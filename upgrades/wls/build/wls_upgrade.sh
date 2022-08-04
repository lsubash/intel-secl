#!/bin/bash

SERVICE_NAME="workload-service"
NEW_EXEC_NAME="wls"
OLD_EXEC_NAME="workload-service"
CURRENT_VERSION=v5.0.0
BACKUP_PATH=${BACKUP_PATH:-"/tmp/"}
LOG_FILE=${LOG_FILE:-"/tmp/$OLD_EXEC_NAME-upgrade.log"}
INSTALLED_EXEC_PATH="/opt/$OLD_EXEC_NAME/bin/$OLD_EXEC_NAME"
CONFIG_PATH="/etc/$OLD_EXEC_NAME"
echo "" >$LOG_FILE

./upgrade.sh -s $SERVICE_NAME -v $CURRENT_VERSION -e $INSTALLED_EXEC_PATH -c $CONFIG_PATH -n $NEW_EXEC_NAME -o $OLD_EXEC_NAME -b $BACKUP_PATH |& tee -a $LOG_FILE
exit ${PIPESTATUS[0]}