#!/bin/bash
set -x

# localhost other_pdx sfo london mumbai
servers=("127.0.0.1" "172.31.24.252" "54.219.21.67" "18.134.127.104" "15.207.62.158")
# ecdhe kyber bike sike
security_policies=(default KMS-PQ-TLS-1-0-2020-07 KMS-PQ-TLS-1-0-2020-02 PQ-SIKE-TEST-TLS-1-0-2020-02)
filenames=(
"ecdhe_us_west_2a_to_localhost" "kyber_us_west_2a_to_localhost" "bike_us_west_2a_to_localhost" "sike_us_west_2a_to_localhost"
"ecdhe_us_west_2a_to_us_west_2b" "kyber_us_west_2a_to_us_west_2b" "bike_us_west_2a_to_us_west_2b" "sike_us_west_2a_to_us_west_2b"
"ecdhe_us_west_2a_to_us_west_1a" "kyber_us_west_2a_to_us_west_1a" "bike_us_west_2a_to_us_west_1a" "sike_us_west_2a_to_us_west_1a"
"ecdhe_us_west_2a_to_eu_west_2b" "kyber_us_west_2a_to_eu_west_2b" "bike_us_west_2a_to_eu_west_2b" "sike_us_west_2a_to_eu_west_2b"
"ecdhe_us_west_2a_to_ap_south_1c" "kyber_us_west_2a_to_ap_south_1c" "bike_us_west_2a_to_ap_south_1c" "sike_us_west_2a_to_ap_south_1c"
)

filename_index=0

for server in "${servers[@]}"; do
    for policy in "${security_policies[@]}"; do
        ./bin/s2nc -i -b 10 --benchmarkfile ${filenames[$filename_index]} -c "$policy" ${server} 8888;
        let "filename_index += 1";
    done
done

