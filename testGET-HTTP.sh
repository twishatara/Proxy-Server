#!/bin/bash

# Tests GET requests
# The URL of your proxy server
PROXY_URL="127.0.0.1:8080"

# The target URL you want to request through your proxy
TARGET_URL="http://www.google.com"

# Number of requests to send
REQUEST_COUNT=10

for i in $(seq 1 $REQUEST_COUNT); do
  echo "Sending request $i"
  curl -x $PROXY_URL $TARGET_URL
  echo -e "\n" # New line for readability
done
