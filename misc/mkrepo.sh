#! /bin/sh
#
# This script builds an minimal example RPKI repository using the mkrpki
# binary and validates it using Routinator

MKRPKI=../target/debug/mkrpki
ROUTINATOR=routinator

echo "--- Preparing repository"

rm -rf ./test-repo
mkdir -p test-repo/keys/
mkdir -p test-repo/tals/
mkdir -p test-repo/repository/rpki.example.com/repo/isp


# Keys
#
$MKRPKI key \
	--private test-repo/keys/ta.key \
	--public test-repo/keys/ta.pub
$MKRPKI key \
	--private test-repo/keys/isp.key \
	--public test-repo/keys/isp.pub

# Trust Anchor CA
#
# CA cert, CRL, ISP CA cert, MFT.
$MKRPKI ta \
	--ca-repository rsync://rpki.example.com/repo/ \
	--key test-repo/keys/ta.key \
	--rpki-manifest rsync://rpki.example.com/repo/ta.mft \
	--serial 1 \
	--tal-rsync-uri rsync://rpki.example.com/repo/ta.cer \
	--days 30 \
	--v4 0.0.0.0/0 \
	--v6 ::/0 \
	--as AS0-AS4000000000 \
	--output test-repo/repository/rpki.example.com/repo/ta.cer \
	--output-tal test-repo/tals/example.tal

$MKRPKI crl \
	--issuer-key test-repo/keys/ta.key \
	--next-days 30 \
	--crl 1 \
	--output test-repo/repository/rpki.example.com/repo/ta.crl

$MKRPKI cer \
	--issuer-key test-repo/keys/ta.key \
	--subject-key test-repo/keys/isp.pub \
	--serial 12 \
	--days 30 \
	--crl rsync://rpki.example.com/repo/ta.crl \
	--ca-issuer rsync://rpki.example.com/repo/ta.cer \
	--ca-repository rsync://rpki.example.com/repo/isp/ \
	--rpki-manifest rsync://rpki.example.com/repo/isp/isp.mft \
	--v4 192.0.2.0/24 \
	--v6 2001:db8::/32 \
	--as AS64494 \
	--output test-repo/repository/rpki.example.com/repo/isp.cer

$MKRPKI mft \
	--issuer-key test-repo/keys/ta.key \
	--serial 83 \
	--days 30 \
	--crl rsync://rpki.example.com/repo/ta.crl \
	--ca-issuer rsync://rpki.example.com/repo/ta.cer \
	--signed-object rsync://rpki.example.com/repo/ta.mft \
	--number 1 \
	--next-days 30 \
	--files \
		test-repo/repository/rpki.example.com/repo/ta.crl \
		test-repo/repository/rpki.example.com/repo/isp.cer \
	--output test-repo/repository/rpki.example.com/repo/ta.mft

# ISP CA
#
# CRL, ROA, MFT.
#
$MKRPKI crl \
	--issuer-key test-repo/keys/isp.key \
	--next-days 30 \
	--crl 1 \
	--output test-repo/repository/rpki.example.com/repo/isp/isp.crl

$MKRPKI roa \
	--issuer-key test-repo/keys/isp.key \
	--serial 321098 \
	--days 30 \
	--crl rsync://rpki.example.com/repo/isp/isp.crl \
	--ca-issuer rsync://rpki.example.com/repo/isp.cer \
	--signed-object rsync://rpki.example.com/repo/isp/isp.roa \
	--asn AS64494 \
	--prefixes 192.0.2.0/24 2001:db8::/32-40 \
	--output test-repo/repository/rpki.example.com/repo/isp/isp.roa

$MKRPKI mft \
	--issuer-key test-repo/keys/isp.key \
	--serial 2398471 \
	--days 30 \
	--crl rsync://rpki.example.com/repo/isp/isp.crl \
	--ca-issuer rsync://rpki.example.com/repo/isp.cer \
	--signed-object rsync://rpki.example.com/repo/isp/isp.mft \
	--number 1 \
	--next-days 30 \
	--files \
		test-repo/repository/rpki.example.com/repo/isp/isp.crl \
		test-repo/repository/rpki.example.com/repo/isp/isp.roa \
	--output test-repo/repository/rpki.example.com/repo/isp/isp.mft

echo "\n\n--- Validating repository"
$ROUTINATOR -b test-repo vrps -n
