#!/bin/bash

set -e  # Exit on error

GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Step 1: Install NPM dependencies${NC}"
npm i

echo -e "${GREEN}🏗️  Step 2: Compile Circom circuit (attest.circom)${NC}"
circom attest.circom --wasm --r1cs -l node_modules

# echo -e "${GREEN}🧱 Step 3: Build C++ witness generator${NC}"
# cd attest_cpp/
# make
# cd ..

echo -e "${GREEN}🧠 Step 4: Generate witness using input.json${NC}"
start_witness=$(gdate +%s%3N)
node attest_js/generate_witness.js attest_js/attest.wasm input.json witness.wtns
end_witness=$(gdate +%s%3N)
echo -e "${GREEN}✅ Witness generated in $((end_witness - start_witness))s${NC}"

echo -e "${GREEN}⚡ Step 5: Generate new Powers of Tau (ptau) file${NC}"
snarkjs powersoftau new bn128 15 pot15_0000.ptau

echo -e "${GREEN}🔧 Step 6: Prepare phase 2 for Groth16${NC}"
snarkjs powersoftau prepare phase2 pot15_0000.ptau pot12_final.ptau 

echo -e "${GREEN}📐 Step 7: Setup Groth16 proving key${NC}"
snarkjs groth16 setup attest.r1cs pot12_final.ptau proving.zkey

echo -e "${GREEN}🧾 Step 8: Export verification key${NC}"
snarkjs zkey export verificationkey proving.zkey verification_key.json

echo -e "${GREEN}⏱️  Step 9: Prove using Groth16${NC}"
start_prove=$(gdate +%s%3N)
snarkjs groth16 prove proving.zkey witness.wtns proof.json public.json
end_prove=$(gdate +%s%3N)
echo -e "${GREEN}✅ Proof generated in $((end_prove - start_prove))s${NC}"

echo -e "${GREEN}🔍 Step 10: Verify the proof${NC}"
start_verify=$(gdate +%s%3N)
snarkjs groth16 verify verification_key.json public.json proof.json
end_verify=$(gdate +%s%3N)
echo -e "${GREEN}✅ Verification completed in $((end_verify - start_verify))s${NC}"

(gdate +%s%3N)