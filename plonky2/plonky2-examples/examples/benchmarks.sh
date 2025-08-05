#!/bin/bash

# Set up
runs=100
labels=("device 1" "device 2" "device 1 optional" "device 2 optional" "device 3 aggr")
counts=(0 0 0 0 0)
sums=(0 0 0 0 0)

echo "Running $runs iterations..."

# Repeat 100 times
for ((i=1; i<=runs; i++)); do
    # Run the example and capture output
    output=$(RUSTFLAGS="-Ctarget-cpu=native" cargo run --release --example piranhas 2>&1)

    # Extract the first 5 times like '1.2345s to prove'
    times=($(echo "$output" | grep -oE '[0-9]+\.[0-9]+s to prove' | head -n 5 | grep -oE '[0-9]+\.[0-9]+'))

    # Check we got exactly 5 values
    if [ "${#times[@]}" -ne 5 ]; then
        echo "⚠️  Run $i: Skipped — did not find 5 valid timing values."
        continue
    fi

    # Accumulate
    for j in {0..4}; do
        sums[$j]=$(echo "${sums[$j]} + ${times[$j]}" | bc)
        counts[$j]=$((counts[$j] + 1))
    done

    # Progress info
    if (( i % 1 == 0 )); then
        echo "Completed $i runs..."
    fi
done

echo ""
echo "✅ Averages after $runs runs (successful runs per label shown):"
for j in {0..4}; do
    if [ "${counts[$j]}" -eq 0 ]; then
        echo "${labels[$j]}: no data"
    else
        avg=$(echo "scale=4; ${sums[$j]} / ${counts[$j]}" | bc)
        echo "${labels[$j]} (${counts[$j]} runs): average = ${avg}s"
    fi
done
