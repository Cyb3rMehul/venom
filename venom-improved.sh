#!/bin/bash

# Exit immediately if any command fails
set -e

# Check if sufficient arguments are passed
if [ $# -lt 5 ]; then
    echo "Usage: $0 <domain> <output_dir> <dns_resolver> <verification_resolver> <alt_dns_wordlist>"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR=$2
DNS_RESOLVER=$3
VERIFICATION_RESOLVER=$4
ALT_DNS_WORDLIST=$5

# Create necessary directories
echo "[*] Creating directories for $DOMAIN..."
mkdir -p $OUTPUT_DIR/$DOMAIN/aquatone/subs
mkdir -p $OUTPUT_DIR/$DOMAIN/aquatone/ip

# Create base directories for tools' outputs
mkdir -p $OUTPUT_DIR/$DOMAIN/amass
mkdir -p $OUTPUT_DIR/$DOMAIN/subfinder
mkdir -p $OUTPUT_DIR/$DOMAIN/sublist3r
mkdir -p $OUTPUT_DIR/$DOMAIN/altdns
mkdir -p $OUTPUT_DIR/$DOMAIN/massdns

# Run subdomain scraping tools
echo "[*] Running scraping tools..."

# Run Amass in background
amass enum -d $DOMAIN -o $OUTPUT_DIR/$DOMAIN/amass/amass.lst &

# Run Subfinder in background
subfinder -v -d $DOMAIN -o $OUTPUT_DIR/$DOMAIN/subfinder/subfinder.lst &

# Run Sublist3r in background
sublist3r -v -d $DOMAIN -o $OUTPUT_DIR/$DOMAIN/sublist3r/sublist3r.lst &

# Wait for all tools to finish
wait

# Merge the lists scraped by all tools
echo "[*] Merging subdomain lists from Amass, Subfinder, and Sublist3r..."
sort -u $OUTPUT_DIR/$DOMAIN/amass/amass.lst $OUTPUT_DIR/$DOMAIN/subfinder/subfinder.lst $OUTPUT_DIR/$DOMAIN/sublist3r/sublist3r.lst > $OUTPUT_DIR/$DOMAIN/scraped.lst

# Run AltDNS on the scraped list to find permuted subdomains
echo "[*] Running AltDNS to find permuted subdomains..."
altdns -i $OUTPUT_DIR/$DOMAIN/scraped.lst -w $ALT_DNS_WORDLIST -o $OUTPUT_DIR/$DOMAIN/altdns/altdns.lst

# Merge scraped subdomains with AltDNS results
echo "[*] Merging scraped subdomains with AltDNS results..."
sort -u -S 50% $OUTPUT_DIR/$DOMAIN/scraped.lst $OUTPUT_DIR/$DOMAIN/altdns/altdns.lst > $OUTPUT_DIR/$DOMAIN/possiblealt.lst

# Use MassDNS to resolve the possible subdomains
echo "[*] Resolving subdomains using MassDNS..."
massdns -s 5000 -r $DNS_RESOLVER $OUTPUT_DIR/$DOMAIN/possiblealt.lst -o J -w $OUTPUT_DIR/$DOMAIN/massdns/mass_unverified.json

# Extract subdomains from massdns output
echo "[*] Extracting subdomains from MassDNS output..."
cat $OUTPUT_DIR/$DOMAIN/massdns/mass_unverified.json | jq -r '.[] | select(.type == "A") | .host' > $OUTPUT_DIR/$DOMAIN/mass_unverified.lst

# Verify resolved subdomains using another DNS resolver
echo "[*] Verifying resolved subdomains using MassDNS..."
massdns -s 4 -r $VERIFICATION_RESOLVER $OUTPUT_DIR/$DOMAIN/mass_unverified.lst -o J -w $OUTPUT_DIR/$DOMAIN/massdns/mass_verified.json

# Extract verified subdomains and their IPs
echo "[*] Extracting verified subdomains and IP addresses..."
cat $OUTPUT_DIR/$DOMAIN/massdns/mass_verified.json | jq -r '.[] | select(.type == "A") | .host + ":" + .ip' > $OUTPUT_DIR/$DOMAIN/subdomains.lst
cat $OUTPUT_DIR/$DOMAIN/massdns/mass_verified.json | jq -r '.[] | select(.type == "A") | .ip' > $OUTPUT_DIR/$DOMAIN/ip.lst

# Run Masscan to find open ports on the discovered IPs
echo "[*] Scanning IPs for open ports using Masscan..."
masscan -p1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151,1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060,5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-522
