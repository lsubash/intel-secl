#!/bin/bash

if [[ -z $HVS_BASE_URL && -z $FDS_BASE_URL ]] ; then
  echo "HVS_BASE_URL 0r FDS_BASE_URL is required for the upgrade to v5.0.0"
  exit 1
fi
