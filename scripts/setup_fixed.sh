#!/bin/bash

# Wait for BMv2 to be ready
sleep 2

echo "🔧 Configuring switch with fixed MACs..."

simple_switch_CLI --thrift-port 9090 << EOF
table_clear mac_table
table_add mac_table forward 00:00:00:00:00:01 => 1
table_add mac_table forward 00:00:00:00:00:02 => 2
table_add mac_table forward 00:00:00:00:00:03 => 3
table_add mac_table forward 00:00:00:00:00:04 => 4
table_set_default mac_table forward 1
table_dump mac_table
quit
EOF

echo "✅ Switch configured!"
