#!/bin/bash

cd /clamd-client
clamd --config-file src/test/docker/clamd.conf --log=/tmp/clamd.log
mvn integration-test surefire-report:report-only surefire-report:failsafe-report-only verify