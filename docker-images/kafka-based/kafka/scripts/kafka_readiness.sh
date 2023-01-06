#!/usr/bin/env bash
set -e

if [ "$STRIMZI_KRAFT_ENABLED" = "true" ]; then
  # Test KRaft controller process is running
  . ./kafka_controller_liveness.sh
else
  # Test ZK-based broker readiness
  # The kafka-agent will create /var/opt/kafka/kafka-ready in the container when the broker
  # state is >= 3 && != 127 (UNKNOWN state)
  test -f /var/opt/kafka/kafka-ready
fi
