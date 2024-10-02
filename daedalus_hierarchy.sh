#!/bin/bash
################################################################################
#
# daedalus_hierarchy.sh
# Creates a complex maze of x509 certificates for testing AIA/SIA on localhost.
#
# tested on Kali Linux 2024.2 [OpenSSL 3.2.2]
#
# Steps to reproduce:
#
# 1) download:
#    https://old.kali.org/kali-images/
#    * kali-linux-2024.2-live-amd64.iso.torrent
#
# 2) download:
#    https://debian.pkgs.org/12/debian-main-amd64/libfaketime_0.9.10-2.1_amd64.deb.html
#    https://debian.pkgs.org/12/debian-main-amd64/faketime_0.9.10-2.1_amd64.deb.html
#
# 3) install:
#    $ sudo apt install ./libfaketime...deb
#    $ sudo apt install ./faketime...deb
#
# 4) RUN:
#    $ faketime "2024-02-11 21:00:00" ./daedalus_hierarchy.sh
#
# Author:
# Leszek Zabłocki
# (c) public domain / MIT
#
################################################################################

# useful links:
# https://docs.openssl.org/master/man5/x509v3_config/
# https://github.com/openssl/openssl/blob/master/crypto/objects/objects.txt

set -o errexit

make_valid_chains_for_debug_in_the_end="yes"

create_aia_bundle="no"
create_sia_bundle="no"

# 7 days, a week of creation without a day's rest
days_100y="$(($(($(date +%s -d "100 years") - $(date +%s)))/$((60*60*24))))"
days_100y_1="$((days_100y - 1))"
days_100y_2="$((days_100y_1 - 1))"
days_100y_3="$((days_100y_2 - 1))"
days_100y_4="$((days_100y_3 - 1))"
days_100y_5="$((days_100y_4 - 1))"
days_100y_6="$((days_100y_5 - 1))"

choice_days="${days_100y}"

custom_cert_serial () {
  echo "$(shuf -i 1-7 -n 1)$(openssl rand -hex 20)" | cut -c1-16
}
serial_hex5 () {
  echo "$(openssl rand -hex 20)" | cut -c1-5
}
serial_alfanum5 () {
  echo "$(LC_ALL=C tr -dc A-Za-z0-9 </dev/urandom | head -c 5)"
}
serial_num5 () {
  echo "$(shuf -i 10000-99999 -n 1)"
}
random_0_99 () {
  echo "$(shuf -i 0-99 -n 1)"
}
random_0_2 () {
  echo "$(shuf -i 0-2 -n 1)"
}
random_0_8 () {
  echo "$(shuf -i 0-8 -n 1)"
}

good_save_the_queen="$(serial_alfanum5)_$(serial_hex5)_$(serial_num5)"

test_dir_alias="$(serial_hex5)"
test_directory="p7c_tests_${test_dir_alias}"

if [ ! -d "${test_directory}" ]; then
  mkdir "${test_directory}"
fi

mkdir "${test_directory}/aia"
mkdir "${test_directory}/sia"

# for "Rebex Tiny Web Server"
website_ca="http://localhost:1180/${test_directory}"
website_ca_ldap="ldap://localhost:1180/${test_directory}"
website_ca_ldaps="ldaps://localhost:1180/${test_directory}"

# https://stackoverflow.com/a/2388555
choice_sha=("sha256" "sha384" "sha512")
random_sha () {
  select_sha="${choice_sha[ $(random_0_2) % ${#choice_sha[@]} ]}"
  echo "${select_sha}"
}

genpkey_rsa2048 () {
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048
}
genpkey_rsa3072 () {
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:3072
}
genpkey_rsa4096 () {
  openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:4096
}
genpkey_secp521r1 () {
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:secp521r1
}
genpkey_secp384r1 () {
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1
}
genpkey_prime256v1 () {
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1
}
genpkey_brainpoolP256r1 () {
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1
}
genpkey_brainpoolP384r1 () {
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP384r1
}
genpkey_brainpoolP512r1 () {
  openssl genpkey -quiet -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP512r1
}
choice_key=("rsa2048" "rsa3072" "rsa4096" "secp521r1" "secp384r1" "prime256v1" "brainpoolP256r1" "brainpoolP384r1" "brainpoolP512r1")
random_key () {
  select_key="${choice_key[ $(random_0_8) % ${#choice_key[@]} ]}"
  echo "${select_key}"
}

x509_AKID_none="authorityKeyIdentifier=none"                               # root ok, int ok
x509_AKID_key="authorityKeyIdentifier=keyid"                               # root X , int ok
x509_AKID_key_root="authorityKeyIdentifier=keyid:always"                   # root ok, int ok
x509_AKID_iss="authorityKeyIdentifier=issuer:always"                       # root ok, int ok
x509_AKID_key_iss="authorityKeyIdentifier=keyid,issuer:always"             # root X , int ok
x509_AKID_key_iss_root="authorityKeyIdentifier=keyid:always,issuer:always" # root ok, int ok

x509_SKID_none="subjectKeyIdentifier=none"
x509_SKID_hash="subjectKeyIdentifier=hash"
x509_SKID_rand () {
  echo "subjectKeyIdentifier=$(openssl rand -hex 20)"
  # like rfc-sha1
}

x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_hash}"

x509_CN="commonName=A root CA"
x509_serialNumber_subject () {
  echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
}
x509_OU="organizationalUnitName=Class 1 CA"
x509_O="organizationName=Mazes & Traps Co."
x509_L="localityName=Knossos"
x509_ST="stateOrProvinceName=Crete"
x509_C="countryName=GR"

x509v3_config_root () {
cat <<-EOF
[ req ]
	distinguished_name = smime_root_dn
	x509_extensions = x509_smime_root_ext
	string_mask = utf8only
	utf8 = yes
	prompt = no
[ smime_root_dn ]
	${x509_CN}
	$(x509_serialNumber_subject)
	${x509_OU}
	${x509_O}
	${x509_L}
	${x509_ST}
	${x509_C}
[ x509_smime_root_ext ]
	basicConstraints = critical,CA:TRUE
	keyUsage = critical,keyCertSign,cRLSign
	${x509_choosed_AKID}
	${x509_choosed_SKID}
	subjectInfoAccess=@subject_info_access
[ subject_info_access ]
	caRepository;URI.0=${website_ca}/sia/cert_B1.der.cer
	caRepository;URI.1=${website_ca}/sia/cert_B2.der.p7c
EOF
}

############################
#
# root part
#
############################
key_A_perm="$(genpkey_$(random_key))"
cert_A_perm="$(openssl req -new -x509 -days "${choice_days}" -"$(random_sha)" -set_serial "0x$(custom_cert_serial)" -config <(echo "$(x509v3_config_root)") -key <(echo "${key_A_perm}"))"
echo "---------------------"
echo "LEVEL A :: ROOT :: ok"
echo "---------------------"

############################
#
# intermediate part
#
############################
x509_basicConstraints="basicConstraints = critical,CA:TRUE"
x509_eku_inter=""
x509_AIA="authorityInfoAccess=@auth_info_access"
x509_AIA_on=""
x509_caIssuers_0=""
x509_caIssuers_1=""
x509_caIssuers_2=""
x509_caIssuers_3=""
x509_SIA="subjectInfoAccess=@subject_info_access"
x509_SIA_on=""
x509_caRepository_0=""
x509_caRepository_1=""
x509_caRepository_2=""

x509v3_config_inter () {
cat <<-EOF
[ req ]
	distinguished_name = smime_inter_dn
	string_mask = utf8only
	utf8 = yes
	prompt = no
[ smime_inter_dn ]
	${x509_CN}
	$(x509_serialNumber_subject)
	${x509_OU}
	${x509_O}
	${x509_L}
	${x509_ST}
	${x509_C}
[ x509_smime_inter_ext ]
	${x509_basicConstraints}
	keyUsage = critical,keyCertSign,cRLSign
	${x509_eku_inter}
	${x509_choosed_AKID}
	${x509_choosed_SKID}
	${x509_AIA_on}
	${x509_SIA_on}
[ auth_info_access ]
	${x509_caIssuers_0}
	${x509_caIssuers_1}
	${x509_caIssuers_2}
	${x509_caIssuers_3}
[ subject_info_access ]
	${x509_caRepository_0}
	${x509_caRepository_1}
	${x509_caRepository_2}
EOF
}
csr_inter () {
  openssl req -new -config <(echo "$(x509v3_config_inter)") -key <(echo "${csr_key_flush}")
}
generate_cert_inter () {
  openssl x509 -req -days "${choice_days}" -"$(random_sha)" -set_serial "0x$(custom_cert_serial)" -in <(echo "$(csr_inter)") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "$(x509v3_config_inter)") -extensions x509_smime_inter_ext
}
unset_flush () {
  unset ca_key_flush
  unset ca_cert_flush
  unset csr_key_flush
}

##############
#
# LEVEL "B"
#
##############
choice_days="${days_100y_1}"
x509_OU="organizationalUnitName=Class 2 CA"


# intermediate B1
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_key}"
x509_choosed_SKID="${x509_SKID_hash}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_B1.pem.p7b"
#
ca_key_flush="${key_A_perm}"
ca_cert_flush="${cert_A_perm}"
key_B1_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_B1_perm}"
x509_CN="commonName=B1 intermediate CA"
cert_B1_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL B1 :: intermediate :: ok"
echo "------------------------------"

# intermediate B2
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_A_${good_save_the_queen}.pem.crt"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_hash}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/cert_C3.pem.crt"
#
ca_key_flush="${key_A_perm}"
ca_cert_flush="${cert_A_perm}"
key_B2_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_B2_perm}"
x509_CN="commonName=B2 intermediate CA"
cert_B2_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL B2 :: intermediate :: ok"
echo "------------------------------"

##############
#
# LEVEL "C"
#
##############
choice_days="${days_100y_2}"
x509_OU="organizationalUnitName=Class 3 CA"


# intermediate C1
x509_eku_inter="extendedKeyUsage = emailProtection"
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_iss}"
x509_choosed_SKID="$(x509_SKID_rand)"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_C1.pem.p7c"
#
ca_key_flush="${key_B1_perm}"
ca_cert_flush="${cert_B1_perm}"
key_C1_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_C1_perm}"
x509_CN="commonName=C1 intermediate CA"
cert_C1_perm="$(generate_cert_inter)"
unset_flush
x509_eku_inter=""
echo "------------------------------"
echo "LEVEL C1 :: intermediate :: ok"
echo "------------------------------"

# intermediate C2
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_B1.der.cer"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_none}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_C2.der.p7b"
#
ca_key_flush="${key_B1_perm}"
ca_cert_flush="${cert_B1_perm}"
key_C2_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_C2_perm}"
x509_CN="commonName=C2 intermediate CA"
cert_C2_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL C2 :: intermediate :: ok"
echo "------------------------------"

# intermediate C3
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_none}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/cert_D3.der.pem"
#
ca_key_flush="${key_B2_perm}"
ca_cert_flush="${cert_B2_perm}"
key_C3_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_C3_perm}"
x509_CN="commonName=C3 intermediate CA"
cert_C3_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL C3 :: intermediate :: ok"
echo "------------------------------"

##############
#
# LEVEL "D"
#
##############
choice_days="${days_100y_3}"
x509_OU="organizationalUnitName=Class 4 CA"


# intermediate D1
x509_eku_inter="extendedKeyUsage = emailProtection"
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_iss}"
x509_choosed_SKID="${x509_SKID_hash}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_D1.der.p7c"
#
ca_key_flush="${key_C2_perm}"
ca_cert_flush="${cert_C2_perm}"
key_D1_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_D1_perm}"
x509_CN="commonName=D1 intermediate CA"
cert_D1_perm="$(generate_cert_inter)"
unset_flush
x509_eku_inter=""
echo "------------------------------"
echo "LEVEL D1 :: intermediate :: ok"
echo "------------------------------"

# intermediate D2
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_C2.pem.der"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_hash}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_D2.pem.p7c"
#
ca_key_flush="${key_C2_perm}"
ca_cert_flush="${cert_C2_perm}"
key_D2_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_D2_perm}"
x509_CN="commonName=D2 intermediate CA"
cert_D2_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL D2 :: intermediate :: ok"
echo "------------------------------"

# intermediate D3
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_C3_B2.pem.p7b"
x509_choosed_AKID="${x509_AKID_iss}"
x509_choosed_SKID="$(x509_SKID_rand)"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/cert_E3.der.cer"
x509_caRepository_1="caRepository;URI.1=${website_ca}/sia/cert_E4.pem.cer"
x509_caRepository_2="caRepository;URI.2=${website_ca}/sia/cert_E5.der.pem"
#
ca_key_flush="${key_C3_perm}"
ca_cert_flush="${cert_C3_perm}"
key_D3_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_D3_perm}"
x509_CN="commonName=D3 intermediate CA"
cert_D3_perm="$(generate_cert_inter)"
unset_flush
x509_caRepository_1=""
x509_caRepository_2=""
echo "------------------------------"
echo "LEVEL D3 :: intermediate :: ok"
echo "------------------------------"

# intermediate D4
x509_eku_inter="extendedKeyUsage = emailProtection"
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="$(x509_SKID_rand)"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_D4.pem.p7b"
#
ca_key_flush="${key_C3_perm}"
ca_cert_flush="${cert_C3_perm}"
key_D4_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_D4_perm}"
x509_CN="commonName=D4 intermediate CA"
cert_D4_perm="$(generate_cert_inter)"
unset_flush
x509_eku_inter=""
echo "------------------------------"
echo "LEVEL D4 :: intermediate :: ok"
echo "------------------------------"

##############
#
# LEVEL "E"
#
##############
choice_days="${days_100y_4}"
x509_OU="organizationalUnitName=Class 5 CA"


# intermediate E1
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_D2.der.pem"
x509_choosed_AKID="${x509_AKID_key_iss}"
x509_choosed_SKID="$(x509_SKID_rand)"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/cert_F1.pem.der"
#
ca_key_flush="${key_D2_perm}"
ca_cert_flush="${cert_D2_perm}"
key_E1_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_E1_perm}"
x509_CN="commonName=E1 intermediate CA"
cert_E1_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL E1 :: intermediate :: ok"
echo "------------------------------"

# intermediate E2
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="$(x509_SKID_rand)"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_E2.der.p7b"
#
ca_key_flush="${key_D2_perm}"
ca_cert_flush="${cert_D2_perm}"
key_E2_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_E2_perm}"
x509_CN="commonName=E2 intermediate CA"
cert_E2_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL E2 :: intermediate :: ok"
echo "------------------------------"

# intermediate E3
x509_serialNumber_subject () {
  echo ""
}
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_D4.der.cer"
x509_choosed_AKID="${x509_AKID_key}"
x509_choosed_SKID="${x509_SKID_hash}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_E3.pem.p7c"
#
ca_key_flush="${key_D3_perm}"
ca_cert_flush="${cert_D3_perm}"
key_E3_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_E3_perm}"
x509_CN="commonName=E3 intermediate CA"
cert_E3_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL E3 :: intermediate :: ok"
echo "------------------------------"
x509_serialNumber_subject () {
  echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
}

# intermediate E4
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_D3.der.cer"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_hash}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/cert_F6.der.crt"
#
ca_key_flush="${key_D3_perm}"
ca_cert_flush="${cert_D3_perm}"
key_E4_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_E4_perm}"
x509_CN="commonName=E4 intermediate CA"
cert_E4_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL E4 :: intermediate :: ok"
echo "------------------------------"

# intermediate E5
x509_eku_inter="extendedKeyUsage = emailProtection"
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_iss}"
x509_choosed_SKID="${x509_SKID_none}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_E5.der.p7c"
#
ca_key_flush="${key_D3_perm}"
ca_cert_flush="${cert_D3_perm}"
key_E5_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_E5_perm}"
x509_CN="commonName=E5 intermediate CA"
cert_E5_perm="$(generate_cert_inter)"
unset_flush
x509_eku_inter=""
echo "------------------------------"
echo "LEVEL E5 :: intermediate :: ok"
echo "------------------------------"

##############
#
# LEVEL "F"
#
##############
choice_days="${days_100y_5}"
x509_OU="organizationalUnitName=Class 6 CA"
x509_eku_inter="extendedKeyUsage = emailProtection"


# intermediate F1
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_E1.pem.crt"
x509_choosed_AKID="${x509_AKID_key}"
x509_choosed_SKID="${x509_SKID_none}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_F1.pem.p7b"
#
ca_key_flush="${key_E1_perm}"
ca_cert_flush="${cert_E1_perm}"
key_F1_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_F1_perm}"
x509_CN="commonName=F1 intermediate CA"
cert_F1_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL F1 :: intermediate :: ok"
echo "------------------------------"

# intermediate F2
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_E1.pem.crt"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_none}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_F2.der.p7c"
#
ca_key_flush="${key_E2_perm}"
ca_cert_flush="${cert_E2_perm}"
key_F2_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_F2_perm}"
x509_CN="commonName=F2 intermediate CA"
cert_F2_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL F2 :: intermediate :: ok"
echo "------------------------------"

# intermediate F3
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_E2.der.p7c"
x509_choosed_AKID="${x509_AKID_iss}"
x509_choosed_SKID="${x509_SKID_hash}"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_F3.pem.p7b"
#
ca_key_flush="${key_E2_perm}"
ca_cert_flush="${cert_E2_perm}"
key_F3_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_F3_perm}"
x509_CN="commonName=F3 intermediate CA"
cert_F3_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL F3 :: intermediate :: ok"
echo "------------------------------"

# intermediate F4
x509_serialNumber_subject () {
  echo ""
}
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/dev/null.der.cer"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="$(x509_SKID_rand)"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_F4.der.p7b"
#
ca_key_flush="${key_E3_perm}"
ca_cert_flush="${cert_E3_perm}"
key_F4_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_F4_perm}"
x509_CN="commonName=F4 intermediate CA"
cert_F4_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL F4 :: intermediate :: ok"
echo "------------------------------"

# intermediate F5
x509_serialNumber_subject () {
  echo ""
}
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/certs_issued_to_E3.der.p7c"
x509_choosed_AKID="${x509_AKID_iss}"
x509_choosed_SKID="$(x509_SKID_rand)"
x509_SIA_on="${x509_SIA}"
x509_caRepository_0="caRepository;URI.0=${website_ca}/sia/certs_issued_by_F5.pem.p7b"
#
ca_key_flush="${key_E3_perm}"
ca_cert_flush="${cert_E3_perm}"
key_F5_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_F5_perm}"
x509_CN="commonName=F5 intermediate CA"
cert_F5_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL F5 :: intermediate :: ok"
echo "------------------------------"
x509_serialNumber_subject () {
  echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
}

# intermediate F6
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_key}"
x509_choosed_SKID="${x509_SKID_none}"
x509_SIA_on=""
#
ca_key_flush="${key_E4_perm}"
ca_cert_flush="${cert_E4_perm}"
key_F6_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_F6_perm}"
x509_CN="commonName=F6 intermediate CA"
cert_F6_perm="$(generate_cert_inter)"
unset_flush
echo "------------------------------"
echo "LEVEL F6 :: intermediate :: ok"
echo "------------------------------"
x509_eku_inter=""

############################
#
# LEVEL "G"
# user part
#
############################
choice_days="${days_100y_6}"
x509_basicConstraints="basicConstraints = critical,CA:FALSE"
x509_AIA_on=""

x509v3_config_user () {
cat <<-EOF
[ req ]
	distinguished_name = smime_user_dn
	string_mask = utf8only
	utf8 = yes
	prompt = no
[ smime_user_dn ]
	${x509_CN}
	${x509_desc}
	$(x509_serialNumber_subject)
	${x509_GN}
	${x509_SN}
	${x509_O}
	${x509_L}
	${x509_ST}
	${x509_C}
[ subject_alt_name ]
	${x509_SAN}
[ x509_smime_user_ext ]
	${x509_basicConstraints}
	${x509_ku_user}
	extendedKeyUsage = emailProtection
	${x509_choosed_AKID}
	${x509_choosed_SKID}
	subjectAltName = @subject_alt_name
	${x509_AIA_on}
[ auth_info_access ]
	${x509_caIssuers_0}
	${x509_caIssuers_1}
	${x509_caIssuers_2}
	${x509_caIssuers_3}
EOF
}
csr_user () {
  openssl req -new -config <(echo "$(x509v3_config_user)") -key <(echo "${csr_key_flush}")
}
generate_cert_user () {
  temp_csr="$(csr_user)"
  user_key_type="$(openssl req -text -noout -in <(echo "${temp_csr}") | awk 'NR == 6 && $0 ~ /rsaEncryption/ {print "rsa"}')"
  if [ "${user_key_type}" == "rsa" ]; then
    x509_ku_user="keyUsage = critical,digitalSignature,keyEncipherment"
  else
    x509_ku_user="keyUsage = critical,digitalSignature,keyAgreement"
  fi
  openssl x509 -req -days "${choice_days}" -"$(random_sha)" -set_serial "0x$(custom_cert_serial)" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "$(x509v3_config_user)") -extensions x509_smime_user_ext
}

# poor Athenians
# https://forebears.io/greece/forenames
choice_gn=("Maria" "Georgios" "Dimitrios" "Ioannis" "Eleni" "Nikolaos" "Konstantin" "Aikaterini" "Christos" "Panagiotis" "Vasiliki" "Vasileios" "Konstantinos" "Sofia" "Athanasios" "Anastasia" "Georgia" "Evangelia" "Eirini" "Anna" "Angeliki" "Dimitra" "Michail" "Ioanna" "Panagiota" "Evangelos" "Antonios" "Emmanouil" "Theodoros" "Despoina" "Spyridon" "Christina" "Anastasios" "Foteini" "Paraskevi" "Andreas" "Ilias" "Kalliopi" "Charalampos" "Alexandra" "Alexandros" "Kyriaki" "Stavros" "Stavroula" "Chrysoula" "Apostolos" "Theodora" "Athina" "Eleftheria" "Petros" "Athanasia" "Stylianos" "Olga" "Sotirios" "Styliani" "Evgenia" "Georg" "Zoi" "Thomas" "Konstantina" "Marina" "Stefanos" "Ioan" "Grigorios" "Eleftherios" "Charikleia" "Dionysios" "Fotios" "Antonia" "Pavlos" "Argyro" "Niki" "Efthymia" "Nikol" "Ourania" "George" "Stamatia" "Angelos" "Margarita" "Efstathios" "Kyriakos" "Chrysanthi" "Afroditi" "Magdalini" "Dimitris" "Effrosyni" "Varvara" "Elissavet" "Pinelopi" "Aristeidis" "Sotiria" "Eftychia" "Polyxeni" "Leonidas" "Spyridoula" "Evanthia" "Efstratios" "Panag" "Nikos" "Aspasia")
random_gn () {
  select_gn="${choice_gn[ $(random_0_99) % ${#choice_gn[@]} ]}"
  echo "${select_gn}"
}
# https://forebears.io/greece/surnames
choice_sn=("Papadopoulos" "Papadopoulou" "Papageorgiou" "Oikonomou" "Papadimitriou" "Georgiou" "Papaioannou" "Pappas" "Vasileiou" "Nikolaou" "Karagiannis" "Vlachos" "Antoniou" "Makris" "Papanikolaou" "Dimitriou" "Ioannidis" "Georgiadis" "Triantafyllou" "Papadakis" "Athanasiou" "Konstantinidis" "Ioannou" "Alexiou" "Christodoulou" "Theodorou" "Giannopoulos" "Nikolaidis" "Konstantinou" "Panagiotopoulos" "Michailidis" "Papakonstantinou" "Papathanasiou" "Antonopoulos" "Dimopoulos" "Karagianni" "Anastasiou" "Dimitriadis" "Pappa" "Vlachou" "Vasileiadis" "Giannakopoulos" "Angelopoulos" "Dimou" "Ioannidou" "Nikolopoulos" "Mylonas" "Stergiou" "Apostolou" "Petropoulos" "Lamprou" "Papadaki" "Christou" "Panagiotou" "Anagnostou" "Makri" "Konstantinidou" "Samaras" "Raptis" "Athanasopoulos" "Alexopoulos" "Christopoulos" "Stavropoulos" "Anagnostopoulos" "Markou" "Georgiadou" "Spanos" "Sidiropoulos" "Antoniadis" "Panagopoulos" "Efthymiou" "Spyropoulos" "Theodoropoulos" "Pavlidis" "Athanasiadis" "Apostolopoulos" "Petrou" "Michalopoulos" "Arvanitis" "Lazaridis" "Kontos" "Georgopoulos" "Panagiotidis" "Theodoridis" "Chatzis" "Anastasiadis" "Papavasileiou" "Papazoglou" "Vasilopoulos" "Iliopoulos" "Kostopoulos" "Politis" "Galanis" "Stavrou" "Apostolidis" "Paraskevopoulos" "Giannopoulou" "Diamantis" "Pantazis" "Andreou")
random_sn () {
  select_sn="${choice_sn[ $(random_0_99) % ${#choice_sn[@]} ]}"
  echo "${select_sn}"
}

# USER G1
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_F1.der.cer"
x509_caIssuers_1="caIssuers;URI.1=${website_ca}/aia/invalid_hello.smime.pem"
x509_caIssuers_2="caIssuers;URI.2=${website_ca}/aia/invalid_late_lament.cms.der"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="$(x509_SKID_rand)"
#
ca_key_flush="${key_F1_perm}"
ca_cert_flush="${cert_F1_perm}"
key_G1_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_G1_perm}"
x509_CN="commonName=G1 user"
x509_GN="givenName=Theseus"
x509_SN=""
x509_SAN="email.0=user_G1@labyrinth.com"
x509_desc="description=But where will you go? / And who will be your guide? /"
cert_G1_perm="$(generate_cert_user)"
unset_flush
x509_caIssuers_1=""
x509_caIssuers_2=""
x509_desc=""
echo "----------------------"
echo "LEVEL G1 :: USER :: ok"
echo "----------------------"

# USER G2
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/degenerate_broken.der.p7c"
x509_caIssuers_1="caIssuers;URI.1=${website_ca}/aia/degenerate_empty.der.p7c"
x509_caIssuers_2="caIssuers;URI.2=${website_ca}/aia/dev/null.der.cer"
x509_choosed_AKID="${x509_AKID_iss}"
x509_choosed_SKID="${x509_SKID_hash}"
#
ca_key_flush="${key_F2_perm}"
ca_cert_flush="${cert_F2_perm}"
key_G2_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_G2_perm}"
x509_CN="commonName=G2 user"
x509_GN="givenName=$(random_gn)"
x509_SN="surname=$(random_sn)"
x509_SAN="email.0=user_G2@labyrinth.com"
cert_G2_perm="$(generate_cert_user)"
unset_flush
x509_caIssuers_1=""
x509_caIssuers_2=""
echo "----------------------"
echo "LEVEL G2 :: USER :: ok"
echo "----------------------"

# USER G3
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_F2.der.cer"
x509_caIssuers_1="caIssuers;URI.1=${website_ca}/aia/dev/null.der.cer"
x509_choosed_AKID="${x509_AKID_key}"
x509_choosed_SKID="${x509_SKID_hash}"
#
ca_key_flush="${key_F3_perm}"
ca_cert_flush="${cert_F3_perm}"
key_G3_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_G3_perm}"
x509_CN="commonName=G3 user"
x509_GN="givenName=$(random_gn)"
x509_SN="surname=$(random_sn)"
x509_SAN="email.0=user_G3@labyrinth.com"
cert_G3_perm="$(generate_cert_user)"
unset_flush
x509_caIssuers_1=""
echo "----------------------"
echo "LEVEL G3 :: USER :: ok"
echo "----------------------"

# USER G4
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_F3.pem.p7b"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="${x509_SKID_hash}"
#
ca_key_flush="${key_F3_perm}"
ca_cert_flush="${cert_F3_perm}"
key_G4_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_G4_perm}"
x509_CN="commonName=G4 user"
x509_GN="givenName=$(random_gn)"
x509_SN="surname=$(random_sn)"
x509_SAN="email.0=user_G4@labyrinth.com"
cert_G4_perm="$(generate_cert_user)"
unset_flush
echo "----------------------"
echo "LEVEL G4 :: USER :: ok"
echo "----------------------"

# USER G5
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/certs_issued_to_F4_part1.der.p7c"
x509_caIssuers_1="caIssuers;URI.1=${website_ca}/aia/certs_issued_to_F4_part2.pem.p7b"
x509_caIssuers_2="caIssuers;URI.2=${website_ca_ldap}/aia/dev/null.der.cer"
x509_caIssuers_3="caIssuers;URI.3=${website_ca}/aia/certs_issued_to_F4_part3.der.p7c"
x509_choosed_AKID="${x509_AKID_key_iss}"
x509_choosed_SKID="${x509_SKID_hash}"
#
ca_key_flush="${key_F4_perm}"
ca_cert_flush="${cert_F4_perm}"
key_G5_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_G5_perm}"
x509_CN="commonName=G5 user"
x509_GN="givenName=$(random_gn)"
x509_SN="surname=$(random_sn)"
x509_SAN="email.0=user_G5@labyrinth.com"
cert_G5_perm="$(generate_cert_user)"
unset_flush
x509_caIssuers_1=""
x509_caIssuers_2=""
x509_caIssuers_3=""
echo "----------------------"
echo "LEVEL G5 :: USER :: ok"
echo "----------------------"

# USER G6
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/certs_issued_to_F5_part1.der.p7c"
x509_caIssuers_1="caIssuers;URI.1=${website_ca_ldaps}/aia/dev/null.der.cer"
x509_caIssuers_2="caIssuers;URI.2=${website_ca}/aia/certs_issued_to_F5_part2.pem.p7b"
x509_choosed_AKID="${x509_AKID_key}"
x509_choosed_SKID="${x509_SKID_hash}"
#
ca_key_flush="${key_F5_perm}"
ca_cert_flush="${cert_F5_perm}"
key_G6_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_G6_perm}"
x509_CN="commonName=G6 user"
x509_GN="givenName=$(random_gn)"
x509_SN="surname=$(random_sn)"
x509_SAN="email.0=user_G6@labyrinth.com"
cert_G6_perm="$(generate_cert_user)"
unset_flush
x509_caIssuers_1=""
x509_caIssuers_2=""
echo "----------------------"
echo "LEVEL G6 :: USER :: ok"
echo "----------------------"

# USER G7
x509_AIA_on="${x509_AIA}"
x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/cert_F6_E4.der.p7c"
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="$(x509_SKID_rand)"
#
ca_key_flush="${key_F6_perm}"
ca_cert_flush="${cert_F6_perm}"
key_G7_perm="$(genpkey_$(random_key))"
csr_key_flush="${key_G7_perm}"
x509_CN="commonName=G7 user"
# At the end of this hierarchy you will find Ariadne. She knows the way to the top (the center of this labyrinth). She is the one.
x509_GN="givenName=Ariadne"
x509_SN=""
x509_SAN="email.0=user_G7@labyrinth.com"
x509_desc="description=And which way will you turn?"
cert_G7_perm="$(generate_cert_user)"
unset_flush
x509_desc=""
echo "----------------------"
echo "LEVEL G7 :: USER :: ok"
echo "----------------------"

# Somewhere in the corner lurks evil.
# USER special guest
choice_days="${days_100y_4}"
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_none}"
x509_choosed_SKID="$(x509_SKID_rand)"
#
ca_key_flush="${key_D4_perm}"
ca_cert_flush="${cert_D4_perm}"
key_minotaur_perm="$(genpkey_rsa2048)"
csr_key_flush="${key_minotaur_perm}"
x509_CN="commonName=Minotaur"
x509_GN="givenName=Asterius"
x509_SN=""
x509_SAN="email.0=minotaur@labyrinth.com"
x509_desc="description=son of Pasiphaë and Cretan Bull"
cert_minotaur_perm="$(generate_cert_user)"
unset_flush
x509_desc=""
echo "-----------------------------------"
echo "LEVEL X :: USER special guest :: ok"
echo "-----------------------------------"

############################
#
# prepare certs to import in apps
#
############################
test_import_dir="IMPORT_THIS_${test_dir_alias}"

if [ ! -d "${test_import_dir}" ]; then
  mkdir "${test_import_dir}"
fi

echo "${cert_G1_perm}" | openssl x509 -inform PEM -outform DER -in /dev/stdin -out "${test_import_dir}/cert_G1.der.cer"
echo "${cert_G2_perm}" | openssl x509 -inform PEM -outform DER -in /dev/stdin -out "${test_import_dir}/cert_G2.der.cer"
echo "${cert_G3_perm}" | openssl x509 -inform PEM -outform DER -in /dev/stdin -out "${test_import_dir}/cert_G3.der.cer"
echo "${cert_G4_perm}" | openssl x509 -inform PEM -outform DER -in /dev/stdin -out "${test_import_dir}/cert_G4.der.cer"
echo "${cert_G5_perm}" | openssl x509 -inform PEM -outform DER -in /dev/stdin -out "${test_import_dir}/cert_G5.der.cer"
echo "${cert_G6_perm}" | openssl x509 -inform PEM -outform DER -in /dev/stdin -out "${test_import_dir}/cert_G6.der.cer"
echo "${cert_G7_perm}" | openssl x509 -inform PEM -outform DER -in /dev/stdin -out "${test_import_dir}/cert_G7.der.cer"

cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/certs_all_users_in_or.der.p7b"
${cert_G1_perm}
${cert_G2_perm}
${cert_G3_perm}
${cert_G4_perm}
${cert_G5_perm}
${cert_G6_perm}
${cert_G7_perm}
EOF

if [ "${make_valid_chains_for_debug_in_the_end}" == "yes" ]; then
mkdir "${test_import_dir}/debug_only_valid_paths"
# user G1
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/debug_only_valid_paths/G1.der.p7b"
${cert_A_perm}
${cert_B1_perm}
${cert_C2_perm}
${cert_D2_perm}
${cert_E1_perm}
${cert_F1_perm}
${cert_G1_perm}
EOF
openssl pkcs7 -inform DER -print_certs -text -in "${test_import_dir}/debug_only_valid_paths/G1.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_import_dir}/debug_only_valid_paths/G1.der.p7b.txt"
# user G2
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/debug_only_valid_paths/G2.der.p7b"
${cert_A_perm}
${cert_B1_perm}
${cert_C2_perm}
${cert_D2_perm}
${cert_E2_perm}
${cert_F2_perm}
${cert_G2_perm}
EOF
openssl pkcs7 -inform DER -print_certs -text -in "${test_import_dir}/debug_only_valid_paths/G2.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_import_dir}/debug_only_valid_paths/G2.der.p7b.txt"
# user G3
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/debug_only_valid_paths/G3.der.p7b"
${cert_A_perm}
${cert_B1_perm}
${cert_C2_perm}
${cert_D2_perm}
${cert_E2_perm}
${cert_F3_perm}
${cert_G3_perm}
EOF
openssl pkcs7 -inform DER -print_certs -text -in "${test_import_dir}/debug_only_valid_paths/G3.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_import_dir}/debug_only_valid_paths/G3.der.p7b.txt"
# user G4
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/debug_only_valid_paths/G4.der.p7b"
${cert_A_perm}
${cert_B1_perm}
${cert_C2_perm}
${cert_D2_perm}
${cert_E2_perm}
${cert_F3_perm}
${cert_G4_perm}
EOF
openssl pkcs7 -inform DER -print_certs -text -in "${test_import_dir}/debug_only_valid_paths/G4.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_import_dir}/debug_only_valid_paths/G4.der.p7b.txt"
# user G5
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/debug_only_valid_paths/G5.der.p7b"
${cert_A_perm}
${cert_B2_perm}
${cert_C3_perm}
${cert_D3_perm}
${cert_E3_perm}
${cert_F4_perm}
${cert_G5_perm}
EOF
openssl pkcs7 -inform DER -print_certs -text -in "${test_import_dir}/debug_only_valid_paths/G5.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_import_dir}/debug_only_valid_paths/G5.der.p7b.txt"
# user G6
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/debug_only_valid_paths/G6.der.p7b"
${cert_A_perm}
${cert_B2_perm}
${cert_C3_perm}
${cert_D3_perm}
${cert_E3_perm}
${cert_F5_perm}
${cert_G6_perm}
EOF
openssl pkcs7 -inform DER -print_certs -text -in "${test_import_dir}/debug_only_valid_paths/G6.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_import_dir}/debug_only_valid_paths/G6.der.p7b.txt"
# user G7
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_import_dir}/debug_only_valid_paths/G7.der.p7b"
${cert_A_perm}
${cert_B2_perm}
${cert_C3_perm}
${cert_D3_perm}
${cert_E4_perm}
${cert_F6_perm}
${cert_G7_perm}
EOF
openssl pkcs7 -inform DER -print_certs -text -in "${test_import_dir}/debug_only_valid_paths/G7.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_import_dir}/debug_only_valid_paths/G7.der.p7b.txt"
fi
echo "----------------------------"
echo "extract certs from var :: ok"
echo "----------------------------"


############################
#
# user G1 AIA
#
############################
openssl x509 -inform PEM -outform DER -in <(echo "${cert_F1_perm}") -out "${test_directory}/aia/cert_F1.der.cer"
# CRLF :
cat <<-EOF | awk -v RS='\r?\n' -v ORS='\r\n' 1 > "${test_directory}/aia/cert_E1.pem.crt"
${cert_E1_perm}
EOF
openssl x509 -inform PEM -outform DER -in <(echo "${cert_D2_perm}") -out "${test_directory}/aia/cert_D2.der.pem"
# no newlines :
cat <<-EOF | awk -v RS='\r?\n' -v ORS='' '{gsub(/-----BEGIN CERTIFICATE-----/,"-----BEGIN CERTIFICATE-----\n"); gsub(/-----END CERTIFICATE-----/,"\n-----END CERTIFICATE-----")}1' > "${test_directory}/aia/cert_C2.pem.der"
${cert_C2_perm}
EOF
openssl x509 -inform PEM -outform DER -in <(echo "${cert_B1_perm}") -out "${test_directory}/aia/cert_B1.der.cer"

# special guest makes itself known (x2)
cat <<"EOF" | awk -v RS='\r?\n' -v ORS='\r\n' 1 | openssl smime -sign -outform PEM -nodetach -nosmimecap -nocerts -signer <(echo "${cert_minotaur_perm}") -keyform PEM -inkey <(echo "${key_minotaur_perm}") -out "${test_directory}/aia/invalid_hello.smime.pem" -md sha256
Content-Type: text/plain; charset=utf-8

hello to you
EOF
#openssl asn1parse -inform PEM -in "${test_directory}/aia/invalid_hello.smime.pem" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/invalid_hello.smime.pem.txt"

cat <<"EOF" | awk -v RS='\r?\n' -v ORS='\r\n' 1 | openssl cms -sign -outform DER -nodetach -keyid -nosmimecap -nocerts -signer <(echo "${cert_minotaur_perm}") -keyform PEM -inkey <(echo "${key_minotaur_perm}") -out "${test_directory}/aia/invalid_late_lament.cms.der" -md sha256 -keyopt rsa_padding_mode:pss -keyopt rsa_pss_saltlen:32
Content-Type: text/plain; charset=utf-8

Cold hearted orb that rules the night,
Removes the colours from our sight.
Red is grey and yellow white,
But we decide which is right.
And which is an illusion?
EOF
#openssl cms -cmsout -print -inform DER -in "${test_directory}/aia/invalid_late_lament.cms.der" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/invalid_late_lament.cms.der.txt"
echo "-----------------"
echo "user G1 AIA :: ok"
echo "-----------------"

############################
#
# user G2 AIA
#
############################
# https://docs.openssl.org/master/man3/ASN1_generate_nconf/
genconf_empty_broken_p7c () {
cat <<-"EOF"
asn1 = SEQUENCE:degenerate_certificates_only_structure
[ degenerate_certificates_only_structure ]
	parameter.0 = OID:1.2.840.113549.1.7.2
	parameter.1 = EXPLICIT:0,SEQUENCE:data
[ data ]
		parameter.0 = INTEGER:1
		parameter.1 = SET:null_set
		parameter.2 = SEQUENCE:data_oid
		parameter.3 = EXPLICIT:0,UTF8:certificates go here
		parameter.4 = EXPLICIT:1,UTF8:crl go here
		parameter.5 = SET:null_set
[ data_oid ]
			parameter.0 = OID:1.2.840.113549.1.7.1
[ null_set ]
EOF
}
openssl asn1parse -genconf <(echo "$(genconf_empty_broken_p7c)") -noout -out "${test_directory}/aia/degenerate_broken.der.p7c"
echo "" | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/aia/degenerate_empty.der.p7c"
echo "-----------------"
echo "user G2 AIA :: ok"
echo "-----------------"

############################
#
# user G3 AIA
#
############################
openssl x509 -inform PEM -outform DER -in <(echo "${cert_F2_perm}") -out "${test_directory}/aia/cert_F2.der.cer"
echo "-----------------"
echo "user G3 AIA :: ok"
echo "-----------------"

############################
#
# user G4 AIA
#
############################
# no newlines :
echo "${cert_F3_perm}" | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin | awk -v RS='\r?\n' -v ORS='' '{gsub(/-----BEGIN PKCS7-----/,"-----BEGIN PKCS7-----\n"); gsub(/-----END PKCS7-----/,"\n-----END PKCS7-----")}1' > "${test_directory}/aia/cert_F3.pem.p7b"
echo "${cert_E2_perm}" | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/aia/cert_E2.der.p7c"
echo "-----------------"
echo "user G4 AIA :: ok"
echo "-----------------"

############################
#
# user G5 AIA
#
############################
# G5 and G6 is one of the most difficult parts in this AIA category. The program has to sift through hundreds of similar CA certificates to find the one that matches. So that it does not have to check signatures every time, it can use certificate sorting by different things (name, s/n, SKID), can queue certificates after checking if SPKI has already been processed, can check if some URL has been processed etc. Multiple CA certificates (F4', F5', E3') simulate renewal/reissue/"name rollover"/"key rollover", except that they must be rejected after signature verification.
#   https://datatracker.ietf.org/doc/html/rfc4158#section-7.2
#   If the
#   AIA is present within a certificate, with a URI [RFC3986] for the
#   issuer's certificate, the certificate processing system (if able) may
#   wish to attempt to retrieve the certificate first from local cache
#   and then by using that URI (because it is expected to point directly
#   to the desired certificate) before attempting to retrieve the
#   certificates that may exist within a directory.
# We are doing unexpected things here (just as Daedalus dealt with unusual projects), so getting the right certificate directly through the AIA will not be so easy.
#
#   https://medium.com/@sleevi_/path-building-vs-path-verifying-the-chain-of-pain-9fbab861d7d6
#   An API should be capable of returning multiple certificates that match a given subject name, so that it can consider all of these when building a certificate path.
##############
# Take a closer look at G5 certificate:
# It has AKID ("x509_AKID_key_iss"), aka FULL-AKID which includes: *keyid F4, *DirName E3, *serial F4.
# This means that by selecting the correct F4, the certificate should contain the same name (Issuer G5 must match Subject F4), should have the same serial number F4 and keyID (AKID in G5 must match SKID in F4).
# We will tinker with these three things here.
# The public key contained in the multiplied F4' certificates is identical to the true F4 certificate.
#
#   https://datatracker.ietf.org/doc/html/rfc4158#section-2.2
#   As discussed in Section 2.4.2, we
#   recommend that subject names and public key pairs are not repeated in
#   paths.
# In this test, repeated certificates with the same public key as "true" certs always contain the wrong signature of the next CA. Ultimately, they must be rejected.
#
#   https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.2
#   The serial number MUST be a positive integer assigned by the CA to
#   each certificate.  It MUST be unique for each certificate issued by a
#   given CA (i.e., the issuer name and serial number identify a unique
#   certificate).
# The multiplexed certificates also have a repeating serial number.
#
#   https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1
#   The
#   referenced CA issuers description is intended to aid certificate
#   users in the selection of a certification path that terminates at a
#   point trusted by the certificate user.
# We will not aid the user here.
#
# Each duplicate F4' certificate has an intentionally bad/damaged (-badsig) signature from the E3 certificate.
# We did 8 combinations when creating multiplied F4' certificates, we will divide them into 3 packages (to make it even more difficult).
# "certs_issued_to_F4_part1.der.p7c" ::
# name    different   |   name    different   |   name    different
# serial  different   |   serial  different   |   serial  the same
# skid    different   |   skid    the same    |   skid    different
# "certs_issued_to_F4_part2.pem.p7b" ::
# name    different   |   name    the same    |   name    the same
# serial  the same    |   serial  different   |   serial  different
# skid    the same    |   skid    different   |   skid    the same
# "certs_issued_to_F4_part3.der.p7c" ::
# name    the same    |   name    the same    |
# serial  the same    |   serial  the same    |
# skid    different   |   skid    the same    |   + 2 x true F4 (obviously 3x"the same")
# Each combination is repeated 13 times. 13 x 8 = 104. 104 + 2 = 106.
# (13 x 3) + (13 x 3) + [(13 x 2) + 2]
# 39 + 39 + 28
# The program that handles sorting/weighting firstly will check 14 certificates (3x"the same"), then rejecting 13 and leaving the real F4. It will also reject the duplicated F4. Before verification, however, you need to obtain the next CA certificate (F4->*E3*, F5->E3->*D3*) that will be missing. So putting these certificates in the cache will be necessary until the next CA is obtained.
# NOTE ms CryptoAPI prefers certificates with a newer renewal date (having a newer date in Not After), so our forgeries would take precedence over the real certificate (before the signature is verified by next CA).

f4_certificate_serial_number="$(openssl x509 -noout -serial -in <(echo "${cert_F4_perm}") | awk -F '=' '{print tolower($NF)}')"
f4_certificate_skid="$(openssl x509 -noout -ext subjectKeyIdentifier -in <(echo "${cert_F4_perm}") | awk 'NR==2 {gsub(/:/,"");print tolower($1)}')"

x509_basicConstraints="basicConstraints = critical,CA:TRUE"
choice_days="${days_100y_5}"
x509_OU="organizationalUnitName=Class 6 CA"
x509_eku_inter="extendedKeyUsage = emailProtection"
x509_AIA_on=""
# Note that the fakes have AKID, while the real certificate does not (forgeries take precedence over the real certificate).
x509_choosed_AKID="${x509_AKID_key}"
ca_key_flush="${key_E3_perm}"
ca_cert_flush="${cert_E3_perm}"
csr_key_flush="${key_F4_perm}"
x509_CN="commonName=F4 intermediate CA"

replicate_cert_F4 () {
  refresh_f4_settings
  temp_csr="$(csr_inter)"
  openssl x509 -badsig -req -days "${choice_days}" -"$(random_sha)" -set_serial "0x${f4_choosed_cert_serial}" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "$(x509v3_config_inter)") -extensions x509_smime_inter_ext
}

make_combination_1_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    f4_choosed_cert_serial="$(custom_cert_serial)"
    x509_choosed_SKID="$(x509_SKID_rand)"
  }
  replicate_cert_F4
done
}
make_combination_2_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    f4_choosed_cert_serial="$(custom_cert_serial)"
    x509_choosed_SKID="subjectKeyIdentifier=${f4_certificate_skid}"
  }
  replicate_cert_F4
done
}
make_combination_3_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    f4_choosed_cert_serial="${f4_certificate_serial_number}"
    x509_choosed_SKID="$(x509_SKID_rand)"
  }
  replicate_cert_F4
done
}
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/aia/certs_issued_to_F4_part1.der.p7c"
$(make_combination_1_F4)
$(make_combination_2_F4)
$(make_combination_3_F4)
EOF
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_F4_part1.der.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/certs_issued_to_F4_part1.der.p7c.txt"

make_combination_4_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    f4_choosed_cert_serial="${f4_certificate_serial_number}"
    x509_choosed_SKID="subjectKeyIdentifier=${f4_certificate_skid}"
  }
  replicate_cert_F4
done
}
make_combination_5_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    f4_choosed_cert_serial="$(custom_cert_serial)"
    x509_choosed_SKID="$(x509_SKID_rand)"
  }
  replicate_cert_F4
done
}
make_combination_6_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    f4_choosed_cert_serial="$(custom_cert_serial)"
    x509_choosed_SKID="subjectKeyIdentifier=${f4_certificate_skid}"
  }
  replicate_cert_F4
done
}
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/aia/certs_issued_to_F4_part2.pem.p7b"
$(make_combination_4_F4)
$(make_combination_5_F4)
$(make_combination_6_F4)
EOF
#openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/aia/certs_issued_to_F4_part2.pem.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/certs_issued_to_F4_part2.pem.p7b.txt"

make_combination_7_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    f4_choosed_cert_serial="${f4_certificate_serial_number}"
    x509_choosed_SKID="$(x509_SKID_rand)"
  }
  replicate_cert_F4
done
}
make_combination_8_F4 () {
for run_f4 in {1..13}; do
  refresh_f4_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    f4_choosed_cert_serial="${f4_certificate_serial_number}"
    x509_choosed_SKID="subjectKeyIdentifier=${f4_certificate_skid}"
  }
  # openssl should create a RANDOM bad signature but it doesn't (in some cases, sha...WithRSA...); so we increase Not Before by about 1 second
  # certificate will have a different fingerprint
  # this only applies to combinations of the same public key and the rest of the stuff (name, SKID, etc.). ::
  sleep 1
  replicate_cert_F4
done
}
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/aia/certs_issued_to_F4_part3.der.p7c"
$(make_combination_7_F4)
$(make_combination_8_F4)
${cert_F4_perm}
${cert_F4_perm}
EOF
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_F4_part3.der.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/certs_issued_to_F4_part3.der.p7c.txt"

# How to verify the chain for this CA?
#
#cat <<-EOF > "G5_chain.pem"
#${cert_A_perm}
#${cert_B2_perm}
#${cert_C3_perm}
#${cert_D3_perm}
#${cert_E3_perm}
#YOUR_CERTIFICATE_F4'
#EOF
#
# $ openssl verify -show_chain -verbose -no_check_time -check_ss_sig -CAfile "G5_chain.pem" "cert_G5.der.cer"
# or
# $ openssl verify -show_chain -verbose -no_check_time -check_ss_sig -partial_chain -CAfile "G5_chain.pem" "cert_G5.der.cer"
# (passes validation of substituted certificates, G5->F4')

echo "------------------------------------"
echo "multiplied F4 certificates AIA :: ok"
echo "------------------------------------"
echo "-----------------"
echo "user G5 AIA :: ok"
echo "-----------------"

############################
#
# user G6 AIA
#
############################
# Take a closer look at G6 certificate:
# It has AKID ("x509_AKID_key"), which includes: *keyid F5.
# This means that by selecting the correct F5, the certificate should contain the same name (Issuer G6 must match Subject F5), should have the same keyID (AKID in G6 must match SKID in F5).
# We will tinker with these two things here.
# The public key contained in the multiplied F5' certificates is different (rand generated) from the real F5 certificate.
# Each duplicate F5' certificate has an intentionally bad/damaged (-badsig) signature from the E3 certificate.
# We did 6 combinations when creating multiplied F5' certificates, we will divide them into 2 packages (to make it even more difficult).
# "certs_issued_to_F5_part1.der.p7c" ::
# name    different   |   name    different   |   name    different   |
# skid    different   |   skid    none        |   skid    the same    |
# "certs_issued_to_F5_part2.pem.p7b" ::
# name    the same    |   name    the same    |   name    the same    |
# skid    different   |   skid    none        |   skid    the same    | + 1 x true F5
# Each combination is repeated 17 times. 17 x 6 = 102. 102 + 1 = 103.
# (17 x 3) + [(17 x 3) + 1]
# 51 + 52
# The program should first reject incompatible public keys. For example, the signature in the G6 certificate is "sha384WithRSAEncryption". Any multiplied F5' certificate that has "Public Key Algorithm: id-ecPublicKey" should be rejected. The program that handles sorting/weighting firstly check 18 certificates, then rejecting 17 and leaving the real F5 (can already do so at this stage).

f5_certificate_skid="$(openssl x509 -noout -ext subjectKeyIdentifier -in <(echo "${cert_F5_perm}") | awk 'NR==2 {gsub(/:/,"");print tolower($1)}')"

x509_basicConstraints="basicConstraints = critical,CA:TRUE"
choice_days="${days_100y_5}"
x509_OU="organizationalUnitName=Class 6 CA"
x509_eku_inter="extendedKeyUsage = emailProtection"
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_none}"
ca_key_flush="${key_E3_perm}"
ca_cert_flush="${cert_E3_perm}"
x509_CN="commonName=F5 intermediate CA"

replicate_cert_F5 () {
  refresh_f5_settings
  csr_key_flush="$(genpkey_$(random_key))"
  temp_csr="$(csr_inter)"
  openssl x509 -badsig -req -days "${choice_days}" -"$(random_sha)" -set_serial "0x$(custom_cert_serial)" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "$(x509v3_config_inter)") -extensions x509_smime_inter_ext
}

make_combination_1_F5 () {
for run_f5 in {1..17}; do
  refresh_f5_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    x509_choosed_SKID="$(x509_SKID_rand)"
  }
  replicate_cert_F5
done
}
make_combination_2_F5 () {
for run_f5 in {1..17}; do
  refresh_f5_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    x509_choosed_SKID="${x509_SKID_none}"
  }
  replicate_cert_F5
done
}
make_combination_3_F5 () {
for run_f5 in {1..17}; do
  refresh_f5_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    x509_choosed_SKID="subjectKeyIdentifier=${f5_certificate_skid}"
  }
  replicate_cert_F5
done
}
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/aia/certs_issued_to_F5_part1.der.p7c"
$(make_combination_1_F5)
$(make_combination_2_F5)
$(make_combination_3_F5)
EOF
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_F5_part1.der.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/certs_issued_to_F5_part1.der.p7c.txt"

make_combination_4_F5 () {
for run_f5 in {1..17}; do
  refresh_f5_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    x509_choosed_SKID="$(x509_SKID_rand)"
  }
  replicate_cert_F5
done
}
make_combination_5_F5 () {
for run_f5 in {1..17}; do
  refresh_f5_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    x509_choosed_SKID="${x509_SKID_none}"
  }
  replicate_cert_F5
done
}
make_combination_6_F5 () {
for run_f5 in {1..17}; do
  refresh_f5_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    x509_choosed_SKID="subjectKeyIdentifier=${f5_certificate_skid}"
  }
  replicate_cert_F5
done
}
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/aia/certs_issued_to_F5_part2.pem.p7b"
$(make_combination_4_F5)
$(make_combination_5_F5)
$(make_combination_6_F5)
${cert_F5_perm}
EOF
#openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/aia/certs_issued_to_F5_part2.pem.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/certs_issued_to_F5_part2.pem.p7b.txt"

echo "------------------------------------"
echo "multiplied F5 certificates AIA :: ok"
echo "------------------------------------"

############################
#
# inter E3 AIA
#
############################
# Take a closer look at F5 certificate:
# It has AKID ("x509_AKID_iss"), which includes: *DirName D3, *serial E3.
# This means that by selecting the correct E3, the certificate should contain the same name (Issuer F5 must match Subject E3), should have the same serial number E3.
# We will tinker with these two things here.
# The public key contained in the multiplied E3' certificates is sometimes identical, sometimes different to the true E3 certificate.
# Certificates that contain the same public key as the real E3 certificate have a bad signature issued by D3.
# Certificates that contain a different public key as the real E3 certificate have a good signature issued by D3.
# We did 4 combinations when creating multiplied E3' certificates:
# "certs_issued_to_E3.der.p7c" ::
# name    different   |   name    different   |
# serial  different   |   serial  the same    |
# -
# name    the same    |   name    the same    |
# serial  different   |   serial  the same    | + 1 x true E3
# There are 24 repetitions with a different public key, 1 (3) x with the same as E3.
# (24 + 1) + (24 + 1) + (24 + 1) + (24 + 3) = 102. 102 + 1 x true E3 = 103.
# The program should first reject incompatible public keys. For example, the signature in the F5 certificate is "sha384WithRSAEncryption". Any multiplied E3' certificate that has "Public Key Algorithm: id-ecPublicKey" should be rejected. The program that handles sorting/weighting firstly check 28 certificates, then rejecting 27 and leaving the real E3. An additional problem may be the obtaining of additional, incorrect certificates fakeD3' for each validation of multiplied E3' certificates (each multiplied E3' certificate has an AIA attribute pointing to fakeD3'), matryoshka (baba w babie).

e3_certificate_serial_number="$(openssl x509 -noout -serial -in <(echo "${cert_E3_perm}") | awk -F '=' '{print tolower($NF)}')"

x509_basicConstraints="basicConstraints = critical,CA:TRUE"
choice_days="${days_100y_4}"
x509_OU="organizationalUnitName=Class 5 CA"
x509_eku_inter=""
x509_AIA_on=""
x509_choosed_AKID="${x509_AKID_key}"
x509_choosed_SKID="${x509_SKID_hash}"
ca_key_flush="${key_D3_perm}"
ca_cert_flush="${cert_D3_perm}"
x509_CN="commonName=E3 intermediate CA"

generate_invalid_cert_aia () {
cat <<-EOF
-----BEGIN CERTIFICATE-----
MIII$(openssl rand -base64 237 | awk -v RS='\r?\n' -v ORS='' 1)
-----END CERTIFICATE-----
EOF
}

replicate_cert_E3 () {
  refresh_e3_settings
  csr_key_flush="$(genpkey_$(random_key))"
  temp_csr="$(csr_inter)"
  openssl x509 -req -days "${choice_days}" -"$(random_sha)" -set_serial "0x${e3_choosed_cert_serial}" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "$(x509v3_config_inter)") -extensions x509_smime_inter_ext
}
replicate_cert_E3_badsig () {
  refresh_e3_settings
  csr_key_flush="${key_E3_perm}"
  temp_csr="$(csr_inter)"
  openssl x509 -badsig -req -days "${choice_days}" -"$(random_sha)" -set_serial "0x${e3_choosed_cert_serial}" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "$(x509v3_config_inter)") -extensions x509_smime_inter_ext
}

make_combination_1a_E3 () {
for run_e3a in {1..24}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    e3_choosed_cert_serial="$(custom_cert_serial)"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  replicate_cert_E3
done
}
make_combination_1b_E3 () {
for run_e3b in {1..1}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    e3_choosed_cert_serial="$(custom_cert_serial)"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  replicate_cert_E3_badsig
done
}

make_combination_2a_E3 () {
for run_e3a in {1..24}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    e3_choosed_cert_serial="${e3_certificate_serial_number}"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  replicate_cert_E3
done
}
make_combination_2b_E3 () {
for run_e3b in {1..1}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo "serialNumber=$(serial_alfanum5)-$(serial_num5)"
	}
    e3_choosed_cert_serial="${e3_certificate_serial_number}"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  replicate_cert_E3_badsig
done
}

make_combination_3a_E3 () {
for run_e3a in {1..24}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    e3_choosed_cert_serial="$(custom_cert_serial)"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  replicate_cert_E3
done
}
make_combination_3b_E3 () {
for run_e3b in {1..1}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    e3_choosed_cert_serial="$(custom_cert_serial)"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  replicate_cert_E3_badsig
done
}

make_combination_4a_E3 () {
for run_e3a in {1..24}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    e3_choosed_cert_serial="${e3_certificate_serial_number}"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  replicate_cert_E3
done
}
make_combination_4b_E3 () {
for run_e3b in {1..3}; do
  refresh_e3_settings () {
	x509_serialNumber_subject () {
      echo ""
	}
    e3_choosed_cert_serial="${e3_certificate_serial_number}"
  }
  invalid_alias="$(openssl rand -hex 4)"
  generate_invalid_cert_aia > "${test_directory}/aia/invalid_${invalid_alias}.pem"
  x509_AIA_on="${x509_AIA}"
  x509_caIssuers_0="caIssuers;URI.0=${website_ca}/aia/invalid_${invalid_alias}.pem"
  # here appears a random element "invalid_...", but still...
  sleep 1
  replicate_cert_E3_badsig
done
}

cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/aia/certs_issued_to_E3.der.p7c"
$(make_combination_1a_E3)
$(make_combination_1b_E3)
$(make_combination_2a_E3)
$(make_combination_2b_E3)
$(make_combination_3a_E3)
$(make_combination_3b_E3)
$(make_combination_4a_E3)
$(make_combination_4b_E3)
${cert_E3_perm}
EOF
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_E3.der.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/certs_issued_to_E3.der.p7c.txt"

echo "------------------------------------"
echo "multiplied E3 certificates AIA :: ok"
echo "------------------------------------"
# where's Wally?
openssl x509 -inform PEM -outform DER -in <(echo "${cert_D4_perm}") -out "${test_directory}/aia/cert_D4.der.cer"
echo "-----------------"
echo "user G6 AIA :: ok"
echo "-----------------"

############################
#
# user G7 AIA
#
############################

cat <<EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/aia/cert_F6_E4.der.p7c"
${cert_F6_perm}
${cert_E4_perm}
EOF
openssl x509 -inform PEM -outform DER -in <(echo "${cert_D3_perm}") -out "${test_directory}/aia/cert_D3.der.cer"
cat <<EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/aia/cert_C3_B2.pem.p7b"
${cert_C3_perm}
${cert_B2_perm}
EOF
openssl x509 -inform PEM -outform PEM -in <(echo "${cert_A_perm}") -out "${test_directory}/aia/cert_A_${good_save_the_queen}.pem.crt"

echo "-----------------"
echo "user G7 AIA :: ok"
echo "-----------------"

if [ "${create_aia_bundle}" == "yes" ]; then
{
openssl x509 -text -in "${test_directory}/aia/cert_A_${good_save_the_queen}.pem.crt"
openssl x509 -text -in "${test_directory}/aia/cert_B1.der.cer"
openssl x509 -text -in "${test_directory}/aia/cert_C2.pem.der"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/aia/cert_C3_B2.pem.p7b"
openssl x509 -text -in "${test_directory}/aia/cert_D2.der.pem"
openssl x509 -text -in "${test_directory}/aia/cert_D3.der.cer"
openssl x509 -text -in "${test_directory}/aia/cert_D4.der.cer"
openssl x509 -text -in "${test_directory}/aia/cert_E1.pem.crt"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/cert_E2.der.p7c"
openssl x509 -text -in "${test_directory}/aia/cert_F1.der.cer"
openssl x509 -text -in "${test_directory}/aia/cert_F2.der.cer"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/aia/cert_F3.pem.p7b"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/cert_F6_E4.der.p7c"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_E3.der.p7c"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_F4_part1.der.p7c"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/aia/certs_issued_to_F4_part2.pem.p7b"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_F4_part3.der.p7c"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/aia/certs_issued_to_F5_part1.der.p7c"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/aia/certs_issued_to_F5_part2.pem.p7b"
} | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/aia/bundle_text.txt"
awk -v RS='\r?\n' -v ORS='' '{gsub(/-----BEGIN CERTIFICATE-----/,"\n-----BEGIN CERTIFICATE-----"); gsub(/-----END CERTIFICATE-----/,"-----END CERTIFICATE-----\n")}1' "${test_directory}/aia/bundle_text.txt" | grep "BEGIN CERTIFICATE" | sort | uniq | awk '{gsub(/BEGIN CERTIFICATE-----/,"BEGIN CERTIFICATE-----\n"); gsub(/-----END CERTIFICATE/,"\n-----END CERTIFICATE");}1' > "${test_directory}/aia/bundle_certs.pem"
openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile "${test_directory}/aia/bundle_certs.pem" -out "${test_directory}/aia/bundle_certs.p7b"
fi

echo "------------------------------------"
echo "Authority Information Access :: DONE"
echo "------------------------------------"


############################
#
# SIA, multiplied
#
############################
x509_basicConstraints="basicConstraints = critical,CA:FALSE"
x509_AIA_on=""

refresh_dead_soul_credentials () {
  x509_GN="givenName=$(random_gn)"
  x509_SN="surname=$(random_sn)"
  x509_SAN="email.0=nobody_$(serial_hex5)_$(serial_num5)@labyrinth.com"
}
csr_user_dead_soul () {
  openssl req -new -config <(echo "$(x509v3_config_user)") -key <(echo "$(genpkey_$(random_key))")
}
generate_cert_user_dead_soul () {
  refresh_dead_soul_settings
  refresh_dead_soul_credentials
  temp_csr="$(csr_user_dead_soul)"
  user_key_type="$(openssl req -text -noout -in <(echo "${temp_csr}") | awk 'NR == 6 && $0 ~ /rsaEncryption/ {print "rsa"}')"
  if [ "${user_key_type}" == "rsa" ]; then
    x509_ku_user="keyUsage = critical,digitalSignature,keyEncipherment"
  else
    x509_ku_user="keyUsage = critical,digitalSignature,keyAgreement"
  fi
  openssl x509 -req -days "${choice_days}" -"$(random_sha)" -set_serial "0x$(custom_cert_serial)" -in <(echo "${temp_csr}") -CA <(echo "${ca_cert_flush}") -CAkey <(echo "${ca_key_flush}") -extfile <(echo "$(x509v3_config_user)") -extensions x509_smime_user_ext
}

make_E5_SIA_certs () {
for run_E5 in {1..38}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_none}"
    x509_choosed_SKID="${x509_SKID_hash}"
    choice_days="1"
    x509_CN="commonName=nobody by E5"
    ca_key_flush="${key_E5_perm}"
    ca_cert_flush="${cert_E5_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by E5
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_E5.der.p7c"
$(make_E5_SIA_certs)
EOF
unset_flush
echo "----------------------------"
echo "LEVEL E5 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_E5.der.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_E5.der.p7c.txt"

make_F5_SIA_certs () {
for run_F5 in {1..38}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_key}"
    x509_choosed_SKID="${x509_SKID_hash}"
    choice_days="2"
    x509_CN="commonName=nobody by F5"
    ca_key_flush="${key_F5_perm}"
    ca_cert_flush="${cert_F5_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by F5
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_F5.pem.p7b"
$(make_F5_SIA_certs)
${cert_G6_perm}
EOF
unset_flush
echo "----------------------------"
echo "LEVEL F5 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_F5.pem.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_F5.pem.p7b.txt"

make_F4_SIA_certs () {
for run_F4 in {1..38}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_key_iss}"
    x509_choosed_SKID="${x509_SKID_hash}"
    choice_days="3"
    x509_CN="commonName=nobody by F4"
    ca_key_flush="${key_F4_perm}"
    ca_cert_flush="${cert_F4_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by F4
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_F4.der.p7b"
$(make_F4_SIA_certs)
${cert_G5_perm}
EOF
unset_flush
echo "----------------------------"
echo "LEVEL F4 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_F4.der.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_F4.der.p7b.txt"

make_C1_SIA_certs () {
for run_C1 in {1..39}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_iss}"
    x509_choosed_SKID="${x509_SKID_hash}"
    choice_days="4"
    x509_CN="commonName=nobody by C1"
    ca_key_flush="${key_C1_perm}"
    ca_cert_flush="${cert_C1_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by C1
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_C1.pem.p7c"
$(make_C1_SIA_certs)
EOF
unset_flush
echo "----------------------------"
echo "LEVEL C1 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_C1.pem.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_C1.pem.p7c.txt"

make_D1_SIA_certs () {
for run_D1 in {1..39}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_key}"
    x509_choosed_SKID="${x509_SKID_hash}"
    choice_days="5"
    x509_CN="commonName=nobody by D1"
    ca_key_flush="${key_D1_perm}"
    ca_cert_flush="${cert_D1_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by D1
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_D1.der.p7c"
$(make_D1_SIA_certs)
EOF
unset_flush
echo "----------------------------"
echo "LEVEL D1 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_D1.der.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_D1.der.p7c.txt"

make_F3_SIA_certs () {
for run_F3 in {1..38}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_key}"
    x509_choosed_SKID="${x509_SKID_hash}"
    choice_days="6"
    x509_CN="commonName=nobody by F3"
    ca_key_flush="${key_F3_perm}"
    ca_cert_flush="${cert_F3_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by F3
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_F3.pem.p7b"
$(make_F3_SIA_certs)
${cert_G3_perm}
${cert_G4_perm}
EOF
unset_flush
echo "----------------------------"
echo "LEVEL F3 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_F3.pem.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_F3.pem.p7b.txt"

make_F2_SIA_certs () {
for run_F2 in {1..38}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_none}"
    x509_choosed_SKID="${x509_SKID_hash}"
    choice_days="7"
    x509_CN="commonName=nobody by F2"
    ca_key_flush="${key_F2_perm}"
    ca_cert_flush="${cert_F2_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by F2
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_F2.der.p7c"
$(make_F2_SIA_certs)
${cert_G2_perm}
EOF
unset_flush
echo "----------------------------"
echo "LEVEL F2 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_F2.der.p7c" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_F2.der.p7c.txt"

make_F1_SIA_certs () {
for run_F1 in {1..38}; do
  refresh_dead_soul_settings () {
    x509_choosed_AKID="${x509_AKID_iss}"
    x509_choosed_SKID="$(x509_SKID_rand)"
    choice_days="8"
    x509_CN="commonName=nobody by F1"
    ca_key_flush="${key_F1_perm}"
    ca_cert_flush="${cert_F1_perm}"
  }
  generate_cert_user_dead_soul
done
}
# issued by F1
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_F1.pem.p7b"
$(make_F1_SIA_certs)
${cert_G1_perm}
EOF
unset_flush
echo "----------------------------"
echo "LEVEL F1 :: dead souls :: ok"
echo "----------------------------"
#openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_F1.pem.p7b" | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/certs_issued_by_F1.pem.p7b.txt"

############################
#
# SIA other
#
############################

# A root
openssl x509 -inform PEM -outform DER -in <(echo "${cert_B1_perm}") -out "${test_directory}/sia/cert_B1.der.cer"
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/sia/cert_B2.der.p7c"
${cert_B2_perm}
EOF
# intermediate B1
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_B1.pem.p7b"
${cert_C1_perm}
${cert_C2_perm}
EOF
# intermediate B2
openssl x509 -inform PEM -outform PEM -in <(echo "${cert_C3_perm}") -out "${test_directory}/sia/cert_C3.pem.crt"
# intermediate C2
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_C2.der.p7b"
${cert_D1_perm}
${cert_D2_perm}
EOF
# intermediate C3
openssl x509 -inform PEM -outform DER -in <(echo "${cert_D3_perm}") -out "${test_directory}/sia/cert_D3.der.pem"
# intermediate D2
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_D2.pem.p7c"
${cert_E1_perm}
${cert_E2_perm}
EOF
# intermediate D3
openssl x509 -inform PEM -outform DER -in <(echo "${cert_E3_perm}") -out "${test_directory}/sia/cert_E3.der.cer"
openssl x509 -inform PEM -outform PEM -in <(echo "${cert_E4_perm}") -out "${test_directory}/sia/cert_E4.pem.cer"
openssl x509 -inform PEM -outform DER -in <(echo "${cert_E5_perm}") -out "${test_directory}/sia/cert_E5.der.pem"
# intermediate D4
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_D4.pem.p7b"
${cert_minotaur_perm}
EOF
# intermediate E1
openssl x509 -inform PEM -outform PEM -in <(echo "${cert_F1_perm}") -out "${test_directory}/sia/cert_F1.pem.der"
# intermediate E2
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_E2.der.p7b"
${cert_F2_perm}
${cert_F3_perm}
EOF
# intermediate E3
cat <<-EOF | openssl crl2pkcs7 -inform PEM -outform PEM -nocrl -certfile /dev/stdin -out "${test_directory}/sia/certs_issued_by_E3.pem.p7c"
${cert_F4_perm}
${cert_F5_perm}
EOF
# intermediate E4
openssl x509 -inform PEM -outform DER -in <(echo "${cert_F6_perm}") -out "${test_directory}/sia/cert_F6.der.crt"

if [ "${create_sia_bundle}" == "yes" ]; then
{
openssl x509 -text -in "${test_directory}/sia/cert_B1.der.cer"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/cert_B2.der.p7c"
openssl x509 -text -in "${test_directory}/sia/cert_C3.pem.crt"
openssl x509 -text -in "${test_directory}/sia/cert_D3.der.pem"
openssl x509 -text -in "${test_directory}/sia/cert_E3.der.cer"
openssl x509 -text -in "${test_directory}/sia/cert_E4.pem.cer"
openssl x509 -text -in "${test_directory}/sia/cert_E5.der.pem"
openssl x509 -text -in "${test_directory}/sia/cert_F1.pem.der"
openssl x509 -text -in "${test_directory}/sia/cert_F6.der.crt"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_B1.pem.p7b"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_C1.pem.p7c"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_C2.der.p7b"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_D1.der.p7c"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_D2.pem.p7c"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_D4.pem.p7b"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_E2.der.p7b"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_E3.pem.p7c"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_E5.der.p7c"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_F1.pem.p7b"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_F2.der.p7c"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_F3.pem.p7b"
openssl pkcs7 -inform DER -print_certs -text -in "${test_directory}/sia/certs_issued_by_F4.der.p7b"
openssl pkcs7 -inform PEM -print_certs -text -in "${test_directory}/sia/certs_issued_by_F5.pem.p7b"
} | awk '{ sub(/[ \t]+$/, ""); print }' > "${test_directory}/sia/bundle_text.txt"
awk -v RS='\r?\n' -v ORS='' '{gsub(/-----BEGIN CERTIFICATE-----/,"\n-----BEGIN CERTIFICATE-----"); gsub(/-----END CERTIFICATE-----/,"-----END CERTIFICATE-----\n")}1' "${test_directory}/sia/bundle_text.txt" | grep "BEGIN CERTIFICATE" | sort | uniq | awk '{gsub(/BEGIN CERTIFICATE-----/,"BEGIN CERTIFICATE-----\n"); gsub(/-----END CERTIFICATE/,"\n-----END CERTIFICATE");}1' > "${test_directory}/sia/bundle_certs.pem"
openssl crl2pkcs7 -inform PEM -outform DER -nocrl -certfile "${test_directory}/sia/bundle_certs.pem" -out "${test_directory}/sia/bundle_certs.p7b"
fi

echo "----------------------------------"
echo "Subject Information Access :: DONE"
echo "----------------------------------"

# test was done with this program:
openssl version -a > "${test_directory}/openssl_version.txt"

cat <<EOF > "checksums.sha256"
$(find . -type f -exec sha256sum {} \; | sort -k 2)
EOF

# check how the variables were assigned at the end of the script's work
#( set -o posix ; set ) > "test.posix.txt"
#compgen -v > "test.compgen.txt"

echo "-----"
echo "DONE."
echo "-----"

# EOF
