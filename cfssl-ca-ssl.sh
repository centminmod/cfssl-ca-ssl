#!/bin/bash
# for centminmod.com LEMP stack installations
cfdir='/etc/cfssl'
servercerts_dir="${cfdir}/servercerts"
clientcerts_dir="${cfdir}/clientcerts"
cfssl_bin='/root/golang/packages/bin/cfssl'

if [ ! -d $cfdir ]; then
  mkdir -p $cfdir
fi

if [[ ! -f "$cfssl_bin" && -f /usr/local/src/centminmod/addons/golang.sh ]]; then
  /usr/local/src/centminmod/addons/golang.sh install
  source /root/.bashrc
  export CC=gcc
  go get -u github.com/cloudflare/cfssl/cmd/cfssl
  go get -u github.com/cloudflare/cfssl/cmd/cfssljson
  if [ -f "$cfssl_bin" ]; then
    cfssl version
  fi
fi

reset_dir() {
  echo "Clear $cfdir"
  rm -f "$cfdir"
}

ca_gen() {
  cd "${cfdir}"
  domain=${1:-centminmod.com}
  expiry=${2:-87600}
  cfssl print-defaults config | sed -e "s|8760h|${expiry}h|g" -e "s|168h|${expiry}h|g" > profile.json
  cfssl print-defaults csr | sed -e "s|example.net|${domain}|g" > "${domain}.csr.json"
  jq --arg expires "${expiry}h" '. + {"CA":{"expiry": $expires,"pathlen":0}}' "${domain}.csr.json" > "${domain}-ca.csr.json"
  cfssl gencert -initca "${domain}-ca.csr.json" | cfssljson -bare "${domain}-ca"
  openssl x509 -in "${domain}-ca.pem" -text -noout
  echo
  if [ -f "${cfdir}/${domain}-ca.pem" ]; then
    echo "ca cert: ${cfdir}/${domain}-ca.pem"
  fi
  if [ -f "${cfdir}/${domain}-ca-key.pem" ]; then
    echo "ca key: ${cfdir}/${domain}-ca-key.pem"
  fi
  if [ -f "${cfdir}/${domain}-ca.csr" ]; then
    echo "ca csr: ${cfdir}/${domain}-ca.csr"
  fi
  if [ -f "${cfdir}/${domain}-ca.csr.json" ]; then
    echo "ca csr profile: ${cfdir}/${domain}-ca.csr.json"
  fi
  if [ -f "${cfdir}/profile.json" ]; then
    echo "ca profile: ${cfdir}/profile.json"
  fi
  echo
}

server_gen() {
  d=${1:-centminmod.com}
  subdomain=${3:-server}
  if [ "$3" ]; then
    serverdomain="${subdomain}.$d"
  else
    serverdomain="$d"
  fi
  domain=${serverdomain}
  expiry=${2:-87600}
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca.pem" && -f "${cfdir}/${d}-ca-key.pem" ]]; then
    mkdir -p "${servercerts_dir}"
    cd "${servercerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    cfssl gencert -config "${cfdir}/profile.json" -profile www -cn "${domain}" -hostname "${domain}" \
          -ca "${cfdir}/${d}-ca.pem" -ca-key "${cfdir}/${d}-ca-key.pem" \
          -hostname "${domain}" "${domain}.csr.json" > "${domain}.json"
    cfssljson -f "${domain}.json" -bare "${domain}"
    openssl x509 -in "${domain}.pem" -text -noout
    echo
    if [ -f "${servercerts_dir}/${domain}.pem" ]; then
      echo "ca cert: ${servercerts_dir}/${domain}.pem"
    fi
    if [ -f "${servercerts_dir}/${domain}-key.pem" ]; then
      echo "ca key: ${servercerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${servercerts_dir}/${domain}.csr" ]; then
      echo "ca csr: ${servercerts_dir}/${domain}.csr"
    fi
    if [ -f "${servercerts_dir}/${domain}.csr.json" ]; then
      echo "ca csr profile: ${servercerts_dir}/${domain}.csr.json"
    fi
    echo
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca.pem\n${cfdir}/${d}-ca-key.pem"
  fi
}

client_gen() {
  d=${1:-centminmod.com}
  subdomain=${3:-client}
  if [ "$3" ]; then
    clientdomain="${subdomain}.$d"
  else
    clientdomain="$d"
  fi
  domain=${clientdomain}
  expiry=${2:-87600}
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca.pem" && -f "${cfdir}/${d}-ca-key.pem" ]]; then
    mkdir -p "${clientcerts_dir}"
    cd "${clientcerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    cfssl gencert -config "${cfdir}/profile.json" -profile client -cn "${domain}" -hostname "${domain}" \
          -ca "${cfdir}/${d}-ca.pem" -ca-key "${cfdir}/${d}-ca-key.pem" \
          -hostname "${domain}" "${domain}.csr.json" > "${domain}.json"
    cfssljson -f "${domain}.json" -bare "${domain}"
    openssl x509 -in "${domain}.pem" -text -noout
    echo
    if [ -f "${clientcerts_dir}/${domain}.pem" ]; then
      echo "ca cert: ${clientcerts_dir}/${domain}.pem"
    fi
    if [ -f "${clientcerts_dir}/${domain}-key.pem" ]; then
      echo "ca key: ${clientcerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${clientcerts_dir}/${domain}.csr" ]; then
      echo "ca csr: ${clientcerts_dir}/${domain}.csr"
    fi
    if [ -f "${clientcerts_dir}/${domain}.csr.json" ]; then
      echo "ca csr profile: ${clientcerts_dir}/${domain}.csr.json"
    fi
    echo
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca.pem\n${cfdir}/${d}-ca-key.pem"
  fi
}

help_function() {
  echo
  echo "Usage:"
  #echo "$0 gen-all domain.com expiryhrs"
  echo "$0 gen-ca domain.com expiryhrs"
  echo "$0 gen-server domain.com expiryhrs server"
  echo "$0 gen-client domain.com expiryhrs client"
}

case "$1" in
  gen-all )
    ca_gen $2 $3
    server_gen $2 $3 $4
    client_gen $2 $3 $4
    ;;
  gen-ca )
    ca_gen $2 $3
    ;;
  gen-server )
    server_gen $2 $3 $4
    ;;
  gen-client )
    client_gen $2 $3 $4
    ;;
  reset )
    reset_dir
    ;;
  * )
    help_function
    ;;
esac