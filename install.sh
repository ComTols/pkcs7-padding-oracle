#!/bin/bash

go version

go build -o bin/padding-oracle cmd/pkcs7-padding-oracle/oracle.go

mkdir -p /usr/local/bin
mkdir -p /etc/padding-oracle
mkdir -p /var/log/padding-oracle

cp bin/padding-oracle /usr/local/bin/padding-oracle
cp padding-oracle.service /etc/systemd/system/padding-oracle.service

systemctl daemon-reload
systemctl enable padding-oracle.service
systemctl start padding-oracle.service
systemctl status padding-oracle.service


