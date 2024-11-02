#!/bin/bash

# Set script location as working dir
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Changing working directory to $SCRIPT_DIR"
cd "$SCRIPT_DIR" || exit

go version

go get all

go build -o bin/padding-oracle cmd/pkcs7-padding-oracle/oracle.go

mkdir -p /usr/local/bin
mkdir -p /etc/padding-oracle
mkdir -p /var/log/padding-oracle

cp bin/padding-oracle /usr/local/bin/padding-oracle

ls -al
./bin/padding-oracle &

sleep 5
