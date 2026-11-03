#!/bin/bash
# Ubuntu 24.04 fresh dedicated EC2 only. No credentials are accepted or printed.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
test "$(id -u)" -eq 0
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=4 -o Acquire::https::Timeout=30 -o APT::Update::Error-Mode=any update -q
apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=4 -o Acquire::https::Timeout=30 install -y -q postgresql-16 postgresql-client-16 postgresql-contrib python3-boto3 python3-psycopg2 ca-certificates curl openssl unzip
if ! command -v aws >/dev/null 2>&1; then
  temporary_dir=$(mktemp -d /tmp/pg-lab-awscli.XXXXXX)
  trap 'rm -rf -- "$temporary_dir"' EXIT
  curl --fail --silent --show-error --connect-timeout 10 --max-time 180 \
    https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o "$temporary_dir/awscliv2.zip"
  unzip -q "$temporary_dir/awscliv2.zip" -d "$temporary_dir"
  "$temporary_dir/aws/install" --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli
fi
install -d -m 0755 /opt/pg-lab/certs
curl --fail --silent --show-error --connect-timeout 10 --max-time 60 \
  https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem \
  -o /opt/pg-lab/certs/us-east-1-bundle.pem
chmod 0644 /opt/pg-lab/certs/us-east-1-bundle.pem
pg_ctlcluster 16 main start || test "$(pg_lsclusters --no-header | awk '$1==16 && $2=="main" {print $4}')" = online
test "$(pg_lsclusters --no-header | awk '$1==16 && $2=="main" {print $4}')" = online
test -f /usr/lib/postgresql/16/lib/test_decoding.so
/usr/bin/python3 -B -c 'import boto3,psycopg2; print("python_dependencies=available")'
pg_lsclusters --no-header
psql --version
aws --version
