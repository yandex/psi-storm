#!/bin/bash

# Benchmark script for PSI step1 performance
# Usage: ./benchmark.sh [num_values] [--keep]
#   num_values: Number of values to process (default: 1000000)
#   --keep:     Keep benchmark files after completion

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

INPUT_FILE="_bench_input.txt"
OUTPUT_FILE="_bench_output.txt"
CONFIG_FILE="_bench_config.ini"
NUM_VALUES=${1:-1000000}  # Default 1M, can override via argument

echo "=== PSI Step1 Benchmark ==="
echo "Generating $NUM_VALUES values..."

# Generate input file (1 to N)
seq 1 "$NUM_VALUES" > "$INPUT_FILE"
echo "Input file: $INPUT_FILE ($(wc -l < "$INPUT_FILE") lines)"

# Generate a random private key
PRIVATE_KEY=$(openssl rand -hex 32)

# Create config file
cat > "$CONFIG_FILE" << EOF
[Keys]
private_key = $PRIVATE_KEY

[Files]
step1_input_file = $INPUT_FILE
step1_output_file = $OUTPUT_FILE
step2_input_file = unused
step2_output_file = unused
EOF

echo ""
echo "Running ../psi step1..."
echo ""

# Run with time
time ../psi step1 --config "$CONFIG_FILE"

echo ""
echo "Output file: $OUTPUT_FILE ($(wc -l < "$OUTPUT_FILE") lines)"

# Calculate throughput
if command -v bc &> /dev/null; then
    echo ""
    echo "To calculate throughput, note the 'real' time above."
fi

# Cleanup (use --keep to keep files)
if [[ "$2" != "--keep" ]]; then
    rm -f "$INPUT_FILE" "$OUTPUT_FILE" "$CONFIG_FILE"
    echo "Benchmark files cleaned up. Use --keep to preserve them."
else
    echo "Files kept: $INPUT_FILE, $OUTPUT_FILE, $CONFIG_FILE"
fi

