#!/bin/bash

# usage: source load_secrets.sh ~/workspace/secrets/sporify.txt

# File containing the key-value pairs
FILE=${1}

# Check if the file exists
if [[ ! -f "$FILE" ]]; then
  echo "File $FILE does not exist."
  exit 1
fi

# Read the file and export the variables
while IFS=": " read -r key value; do
  # Trim leading/trailing whitespace (if needed)
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)
  echo "key: $key, value: $value"

  # Export the variables
  export "$key=$value"
done < "$FILE"

# Confirm the values have been exported
echo "Exported environment variables:"
echo "CLIENT_ID: $CLIENT_ID"
export "CLIENT_ID=$CLIENT_ID"
echo "CLIENT_SECRET: $CLIENT_SECRET"
export "CLIENT_SECRET=$CLIENT_SECRET"
