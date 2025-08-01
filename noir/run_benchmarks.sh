#!/bin/bash

# Define bold green color
BOLD_GREEN="\033[1;32m"
RESET="\033[0m"

# Map folder names to input numbers
FOLDERS=(
    "1-attest-(Pi-zkRA)"
    "2-recurse-(R1)"
    "3-aggregate-(R2)"
    "4-optimized-(R2+R1)"
    "5-optimized-(2xR2+R1)"
)

# Check for valid input
if [ -z "$1" ] || [ "$1" -lt 1 ] || [ "$1" -gt 5 ]; then
    echo "Usage: $0 [1-5]"
    exit 1
fi

FOLDER="${FOLDERS[$(( $1 - 1 ))]}"
echo -e "${BOLD_GREEN}=======================================${RESET}"
echo -e "${BOLD_GREEN}🗂  Entering folder: $FOLDER${RESET}"
echo -e "${BOLD_GREEN}=======================================${RESET}"
cd "$FOLDER" || { echo "❌ Failed to enter directory $FOLDER"; exit 1; }

echo -e "\n${BOLD_GREEN}🚀 Step 1: Executing Nargo${RESET}"
echo "---------------------------------------"
nargo execute
echo "✅ Nargo execution complete"

echo -e "\n${BOLD_GREEN}🚧 Step 2: Proving${RESET}"
echo "---------------------------------------"

if [ "$1" -eq 1 ]; then
    echo "🔧 Using: ultra_honk | attest.json"
    bb prove --zk -v -s ultra_honk -b "./target/attest.json" -w "./target/attest.gz" -o ./proof --output_format bytes_and_fields --honk_recursion 1 --recursive --init_kzg_accumulator
else
    echo "🔧 Using: default | recurse.json"
    bb prove --zk -v -b "./target/recurse.json" -w "./target/recurse.gz" -o ./proof --recursive
fi

echo "✅ Proof generation complete"

echo -e "\n${BOLD_GREEN}🧩 Step 3: Writing Verification Key${RESET}"
echo "---------------------------------------"

if [ "$1" -eq 1 ]; then
    bb write_vk -v -s ultra_honk -b "./target/attest.json" -o ./proof --output_format bytes_and_fields --honk_recursion 1 --init_kzg_accumulator
else
    bb write_vk -v -b "./target/recurse.json" -o ./proof --honk_recursion 1
fi

echo "✅ Verification key written"

echo -e "\n${BOLD_GREEN}🔍 Step 4: Verifying Proof${RESET}"
echo "---------------------------------------"

if [ "$1" -eq 1 ]; then
    bb verify -s ultra_honk -k ./proof/vk -p ./proof/proof
else
    bb verify -k ./proof/vk -p ./proof/proof
fi

echo -e "\n${BOLD_GREEN}🎉 All steps completed successfully in: $FOLDER${RESET}"
echo -e "${BOLD_GREEN}=======================================${RESET}"
