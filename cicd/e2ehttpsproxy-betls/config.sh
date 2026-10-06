#!/bin/bash
# Topology and material for the qualification of the backend leg of an
# end-to-end HTTPS rule. The fixture tool is built here, no binary is
# committed; it needs go, as the other TLS scenarios do for their certificates.
source ../common.sh

go build -o fixture ../common/betls/fixture.go || { echo "could not build the fixture tool"; exit 1; }

echo "#########################################"
echo "Spawning all hosts"
echo "#########################################"

spawn_docker_host --dock-type loxilb --dock-name llb1
spawn_docker_host --dock-type host --dock-name l3h1
spawn_docker_host --dock-type host --dock-name l3ep1
spawn_docker_host --dock-type host --dock-name l3ep2

echo "#########################################"
echo "Connecting and configuring  hosts"
echo "#########################################"

connect_docker_hosts l3h1 llb1
connect_docker_hosts l3ep1 llb1
connect_docker_hosts l3ep2 llb1

sleep 5

config_docker_host --host1 l3h1 --host2 llb1 --ptype phy --addr 10.10.10.1/24 --gw 10.10.10.254
config_docker_host --host1 l3ep1 --host2 llb1 --ptype phy --addr 31.31.31.1/24 --gw 31.31.31.254
config_docker_host --host1 l3ep2 --host2 llb1 --ptype phy --addr 32.32.32.1/24 --gw 32.32.32.254

config_docker_host --host1 llb1 --host2 l3h1 --ptype phy --addr 10.10.10.254/24
config_docker_host --host1 llb1 --host2 l3ep1 --ptype phy --addr 31.31.31.254/24
config_docker_host --host1 llb1 --host2 l3ep2 --ptype phy --addr 32.32.32.254/24

echo "#########################################"
echo "Preparing certificates"
echo "#########################################"

rm -rf pki && mkdir -p pki/receipts
F=./fixture
# The CA the backends are issued from and trust for client certificates, and
# a second CA nothing in the scenario trusts.
$F ca -out pki/ca-a
$F ca -out pki/ca-b

# The gateway's own certificate, the one a client of the VIP sees. It is
# issued by the CA the backends trust and is good for client authentication,
# so a backend would accept it: only the fingerprint the backend reports
# tells it from the client certificate a rule names.
$F leaf -ca pki/ca-a -out pki/default-rsa -alg rsa -ip 10.10.10.254 -usage both
$F leaf -ca pki/ca-a -out pki/default-ecdsa -alg ecdsa -ip 10.10.10.254 -usage both

# Client certificates a rule can name.
$F leaf -ca pki/ca-a -out pki/client-rsa -alg rsa -usage client
$F leaf -ca pki/ca-a -out pki/client-ecdsa -alg ecdsa -usage client
# A pair that is well formed but too weak for the data plane's TLS library.
$F leaf -ca pki/ca-a -out pki/client-weak -alg rsa -bits 1024 -usage client

# Backends in order.
$F leaf -ca pki/ca-a -out pki/good-rsa -alg rsa -ip 31.31.31.1
$F leaf -ca pki/ca-a -out pki/good-ecdsa -alg ecdsa -ip 32.32.32.1
$F leaf -ca pki/ca-a -out pki/dnsonly -alg rsa -dns backend.betls.test
# Backends a verifying gateway must not talk to.
$F leaf -ca pki/ca-b -out pki/wrongca -alg rsa -ip 31.31.31.1
$F leaf -ca pki/ca-a -out pki/expired -alg rsa -ip 31.31.31.1 -expired
$F leaf -ca pki/ca-a -out pki/wrongip -alg rsa -ip 31.31.31.99
$F leaf -ca pki/ca-a -out pki/wrongdns -alg rsa -ip 31.31.31.1 -dns other.betls.test

ls pki/*.crt > /dev/null || { echo "certificates were not generated"; exit 1; }

docker cp pki/ca-a.crt llb1:/opt/loxilb/cert/rootCA.crt
docker cp pki/default-rsa.crt llb1:/opt/loxilb/cert/server.crt
docker cp pki/default-rsa.key llb1:/opt/loxilb/cert/server.key

sleep 5
