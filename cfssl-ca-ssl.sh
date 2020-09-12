#!/bin/bash
# for centminmod.com LEMP stack installations
debug='y'
cfdir='/etc/cfssl'
servercerts_dir="${cfdir}/servercerts"
clientcerts_dir="${cfdir}/clientcerts"
peercerts_dir="${cfdir}/peercerts"
cfssl_bin='/root/golang/packages/bin/cfssl'
cfssljson_bin='/root/golang/packages/bin/cfssljson'
cfsslinfo_bin='/root/golang/packages/bin/cfssl-certinfo'

if [ ! -d $cfdir ]; then
  mkdir -p $cfdir
fi

if [[ ! -f "$cfssl_bin" || ! -f "$cfssljson_bin" || ! -f "$cfsslinfo_bin" ]] && [ -f /usr/local/src/centminmod/addons/golang.sh ]; then
  /usr/local/src/centminmod/addons/golang.sh install
  source /root/.bashrc
  export CC=gcc
  go get -u github.com/cloudflare/cfssl/cmd/cfssl
  go get -u github.com/cloudflare/cfssl/cmd/cfssljson
  go get -u github.com/cloudflare/cfssl/cmd/cfssl-certinfo
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
  # cfssl print-defaults config | sed -e "s|8760h|${expiry}h|g" -e "s|168h|${expiry}h|g" > profile.json
  echo "{\"signing\":{\"default\":{\"expiry\":\"8760h\"},\"profiles\":{\"intermediate_ca\":{\"usages\":[\"signing\",\"digital signature\",\"key encipherment\",\"cert sign\",\"crl sign\",\"server auth\",\"client auth\"],\"expiry\":\"8760h\",\"ca_constraint\":{\"is_ca\":true,\"max_path_len\":0,\"max_path_len_zero\":true}},\"peer\":{\"usages\":[\"signing\",\"digital signature\",\"key encipherment\",\"client auth\",\"server auth\"],\"expiry\":\"8760h\"},\"server\":{\"usages\":[\"signing\",\"digital signing\",\"key encipherment\",\"server auth\"],\"expiry\":\"8760h\"},\"client\":{\"usages\":[\"signing\",\"digital signature\",\"key encipherment\",\"client auth\"],\"expiry\":\"8760h\"}}}}" | jq | sed -e "s|8760h|${expiry}h|g" -e "s|168h|${expiry}h|g" > profile.json

  # ca generation
  echo "--------------------------------------"
  echo "CA generation"
  echo "--------------------------------------"
  # cfssl print-defaults csr | sed -e "s|example.net|${domain}|g" > "${domain}.csr.json"
  # jq --arg expires "${expiry}h" '. + {"CA":{"expiry": $expires,"pathlen":0}}' "${domain}.csr.json" > "${domain}-ca.csr.json"
  echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"www.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"OU\":\"CA\",\"L\":\"San Francisco\"}],\"CA\":{\"expiry\":\"${expiry}h\",\"pathlen\":0}}" | jq > "${domain}-ca.csr.json"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "cfssl gencert -initca ${domain}-ca.csr.json | cfssljson -bare ${domain}-ca"
    echo
  fi
  cfssl gencert -initca "${domain}-ca.csr.json" | cfssljson -bare "${domain}-ca"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "openssl x509 -in ${domain}-ca.pem -text -noout"
    echo
  fi
  openssl x509 -in "${domain}-ca.pem" -text -noout
  echo
  if [ -f "${cfdir}/${domain}-ca.pem" ]; then
    echo "ca cert: ${cfdir}/${domain}-ca.pem"
    certinfo=$(cfssl-certinfo -cert ${cfdir}/${domain}-ca.pem)
  fi
  if [ -f "${cfdir}/${domain}-ca-key.pem" ]; then
    chmod 0600 "${cfdir}/${domain}-ca-key.pem"
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
    echo
  fi
  echo "$certinfo"
  echo

  # ca intermediate generation
  echo "--------------------------------------"
  echo "CA Intermediate generation"
  echo "--------------------------------------"
  cd "${cfdir}"
  # cfssl print-defaults csr | sed -e "s|example.net|${domain}|g" > "${domain}-intermediate.csr.json"
  # jq --arg expires "${expiry}h" '. + {"CA":{"expiry": $expires,"pathlen":0}}' "${domain}-intermediate.csr.json" > "${domain}-ca-intermediate.csr.json"
  echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"www.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"OU\":\"Intermediate CA\",\"L\":\"San Francisco\"}],\"CA\":{\"expiry\":\"${expiry}h\",\"pathlen\":0}}" | jq > "${domain}-ca-intermediate.csr.json"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "cfssl gencert -initca ${domain}-ca-intermediate.csr.json | cfssljson -bare ${domain}-ca-intermediate"
    echo
  fi
  cfssl gencert -initca "${domain}-ca-intermediate.csr.json" | cfssljson -bare "${domain}-ca-intermediate"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "cfssl sign -ca ${cfdir}/${domain}-ca.pem -ca-key ${cfdir}/${domain}-ca-key.pem -config ${cfdir}/profile.json -profile intermediate_ca ${domain}ca-intermediate.csr | cfssljson -bare ${domain}-ca-intermediate"
  fi
  cfssl sign -ca "${cfdir}/${domain}-ca.pem" -ca-key "${cfdir}/${domain}-ca-key.pem" \
        -config "${cfdir}/profile.json" -profile intermediate_ca "${domain}-ca-intermediate.csr" | cfssljson -bare "${domain}-ca-intermediate"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "openssl x509 -in ${domain}-ca-intermediate.pem -text -noout"
    echo
  fi
  openssl x509 -in "${domain}-ca-intermediate.pem" -text -noout
  echo
  if [ -f "${cfdir}/${domain}-ca-intermediate.pem" ]; then
    echo "ca intermediate cert: ${cfdir}/${domain}-ca-intermediate.pem"
    certinfo=$(cfssl-certinfo -cert ${cfdir}/${domain}-ca-intermediate.pem)
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate-key.pem" ]; then
    chmod 0600 "${cfdir}/${domain}-ca-intermediate-key.pem"
    echo "ca intermediate key: ${cfdir}/${domain}-ca-intermediate-key.pem"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate.csr" ]; then
    echo "ca intermediate csr: ${cfdir}/${domain}-ca-intermediate.csr"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate.csr.json" ]; then
    echo "ca intermediate csr profile: ${cfdir}/${domain}-ca-intermediate.csr.json"
  fi
  if [ -f "${cfdir}/profile.json" ]; then
    echo "ca intermediate profile: ${cfdir}/profile.json"
    echo
  fi
  echo "$certinfo"
  echo

  # CA bundle
  cat "${cfdir}/${domain}-ca.pem" "${cfdir}/${domain}-ca-intermediate.pem" > "${cfdir}/${domain}-ca-bundle.pem"
  echo "CA Bundle generated: ${cfdir}/${domain}-ca-bundle.pem"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "cat ${cfdir}/${domain}-ca.pem ${cfdir}/${domain}-ca-intermediate.pem > ${cfdir}/${domain}-ca-bundle.pem"
    echo
  fi
}

server_gen() {
  d=${1:-centminmod.com}
  subdomain=${3:-server}
  if [ "$3" = 'wildcard' ]; then
    serverdomain="$d"
  elif [ "$3" ]; then
    serverdomain="${subdomain}.$d"
  else
    serverdomain="$d"
  fi
  domain=${serverdomain}
  expiry=${2:-87600}
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca-intermediate.pem" && -f "${cfdir}/${d}-ca-intermediate-key.pem" ]]; then
    mkdir -p "${servercerts_dir}"
    cd "${servercerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    if [ "$3" = 'wildcard' ]; then
      echo "{\"CN\":\"${serverdomain}\",\"hosts\":[\"${serverdomain}\",\"*.${serverdomain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile server -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}-ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile server \
            -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
            "${domain}.csr.json" > "${domain}.json"
    else
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile server -cn ${domain} -hostname ${domain} -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile server -cn "${domain}" -hostname "${domain}" \
          -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
          "${domain}.csr.json" > "${domain}.json"
  fi
    if [[ "$debug" = [yY] ]]; then
      echo
        echo "cfssljson -f ${domain}.json -bare ${domain}"
        echo
    fi
    cfssljson -f "${domain}.json" -bare "${domain}"
    if [[ "$debug" = [yY] ]]; then
      echo
        echo "openssl x509 -in "${domain}.pem" -text -noout"
        echo
    fi
    openssl x509 -in "${domain}.pem" -text -noout
    echo
    if [ -f "${servercerts_dir}/${domain}.pem" ]; then
      echo "server cert: ${servercerts_dir}/${domain}.pem"
      certinfo=$(cfssl-certinfo -cert ${servercerts_dir}/${domain}.pem)
    fi
    if [ -f "${servercerts_dir}/${domain}-key.pem" ]; then
      chmod 0600 "${servercerts_dir}/${domain}-key.pem"
      echo "server key: ${servercerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${servercerts_dir}/${domain}.csr" ]; then
      echo "server csr: ${servercerts_dir}/${domain}.csr"
    fi
    if [ -f "${servercerts_dir}/${domain}.csr.json" ]; then
      echo "server csr profile: ${servercerts_dir}/${domain}.csr.json"
      echo
    fi
    echo "Nginx SSL configuration paramaters:"
    echo -e "ssl_certificate      ${servercerts_dir}/${domain}.pem;\nssl_certificate_key  ${servercerts_dir}/${domain}-key.pem;\n"
    echo "$certinfo"
    echo
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca-intermediate.pem\n${cfdir}/${d}-ca-intermediate-key.pem"
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
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca-intermediate.pem" && -f "${cfdir}/${d}-ca-intermediate-key.pem" ]]; then
    mkdir -p "${clientcerts_dir}"
    cd "${clientcerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "cfssl gencert -config ${cfdir}/profile.json -profile client -cn ${domain} -hostname ${domain} -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
    fi
    cfssl gencert -config "${cfdir}/profile.json" -profile client -cn "${domain}" -hostname "${domain}" \
          -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
          "${domain}.csr.json" > "${domain}.json"
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "cfssljson -f ${domain}.json -bare ${domain}"
      echo
    fi
    cfssljson -f "${domain}.json" -bare "${domain}"
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl x509 -in ${domain}.pem -text -noout"
      echo
    fi
    openssl x509 -in "${domain}.pem" -text -noout
    echo
    if [[ -f "${clientcerts_dir}/${domain}-key.pem" && -f "${clientcerts_dir}/${domain}.pem" && -f "${cfdir}/${d}-ca-bundle.pem" ]]; then
      echo "Generate pkcs12 format"
      if [[ "$debug" = [yY] ]]; then
        echo "openssl pkcs12 -export -out ${clientcerts_dir}/${domain}.p12 -inkey ${clientcerts_dir}/${domain}-key.pem -in ${clientcerts_dir}/${domain}.pem -certfile ${cfdir}/${d}-ca-bundle.pem -passin pass: -passout pass:"
        echo
      fi
      openssl pkcs12 -export -out "${clientcerts_dir}/${domain}.p12" -inkey "${clientcerts_dir}/${domain}-key.pem" -in "${clientcerts_dir}/${domain}.pem" -certfile "${cfdir}/${d}-ca-bundle.pem" -passin pass: -passout pass:
      if [ -f "${clientcerts_dir}/${domain}.p12" ]; then
        echo "client pkcs12: ${clientcerts_dir}/${domain}.p12"
      fi
    fi
    if [ -f "${clientcerts_dir}/${domain}.pem" ]; then
      echo "client cert: ${clientcerts_dir}/${domain}.pem"
      certinfo=$(cfssl-certinfo -cert ${clientcerts_dir}/${domain}.pem)
    fi
    if [ -f "${clientcerts_dir}/${domain}-key.pem" ]; then
      chmod 0600 "${clientcerts_dir}/${domain}-key.pem"
      echo "client key: ${clientcerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${clientcerts_dir}/${domain}.csr" ]; then
      echo "client csr: ${clientcerts_dir}/${domain}.csr"
    fi
    if [ -f "${clientcerts_dir}/${domain}.csr.json" ]; then
      echo "client csr profile: ${clientcerts_dir}/${domain}.csr.json"
      echo
    fi
    echo "$certinfo"
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca-intermediate.pem\n${cfdir}/${d}-ca-intermediate-key.pem"
  fi
}

peer_gen() {
  d=${1:-centminmod.com}
  subdomain=${3:-server}
  if [ "$3" = 'wildcard' ]; then
    serverdomain="$d"
  elif [ "$3" ]; then
    serverdomain="${subdomain}.$d"
  else
    serverdomain="$d"
  fi
  domain=${serverdomain}
  expiry=${2:-87600}
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca-intermediate.pem" && -f "${cfdir}/${d}-ca-intermediate-key.pem" ]]; then
    mkdir -p "${peercerts_dir}"
    cd "${peercerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    if [ "$3" = 'wildcard' ]; then
      echo "{\"CN\":\"${serverdomain}\",\"hosts\":[\"${serverdomain}\",\"*.${serverdomain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"

      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile peer -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}-ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile peer \
            -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
            "${domain}.csr.json" > "${domain}.json"
    else
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile peer -cn ${domain} -hostname ${domain} -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile peer -cn "${domain}" -hostname "${domain}" \
            -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
            "${domain}.csr.json" > "${domain}.json"
    fi
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "cfssljson -f ${domain}.json -bare ${domain}"
      echo
    fi
    cfssljson -f "${domain}.json" -bare "${domain}"
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl x509 -in "${domain}.pem" -text -noout"
      echo
    fi
    openssl x509 -in "${domain}.pem" -text -noout
    echo
    if [[ -f "${peercerts_dir}/${domain}-key.pem" && -f "${peercerts_dir}/${domain}.pem" && -f "${cfdir}/${d}-ca-bundle.pem" ]]; then
      echo "Generate pkcs12 format"
      if [[ "$debug" = [yY] ]]; then
        echo "openssl pkcs12 -export -out ${peercerts_dir}/${domain}.p12 -inkey ${peercerts_dir}/${domain}-key.pem -in ${peercerts_dir}/${domain}.pem -certfile ${cfdir}/${d}-ca-bundle.pem -passin pass: -passout pass:"
        echo
      fi
      openssl pkcs12 -export -out "${peercerts_dir}/${domain}.p12" -inkey "${peercerts_dir}/${domain}-key.pem" -in "${peercerts_dir}/${domain}.pem" -certfile "${cfdir}/${d}-ca-bundle.pem" -passin pass: -passout pass:
      if [ -f "${peercerts_dir}/${domain}.p12" ]; then
        echo "peer pkcs12: ${peercerts_dir}/${domain}.p12"
      fi
    fi
    if [ -f "${peercerts_dir}/${domain}.pem" ]; then
      echo "peer cert: ${peercerts_dir}/${domain}.pem"
      certinfo=$(cfssl-certinfo -cert ${peercerts_dir}/${domain}.pem)
    fi
    if [ -f "${peercerts_dir}/${domain}-key.pem" ]; then
      chmod 0600 "${peercerts_dir}/${domain}-key.pem"
      echo "peer key: ${peercerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${peercerts_dir}/${domain}.csr" ]; then
      echo "peer csr: ${peercerts_dir}/${domain}.csr"
    fi
    if [ -f "${peercerts_dir}/${domain}.csr.json" ]; then
      echo "peer csr profile: ${peercerts_dir}/${domain}.csr.json"
      echo
    fi
    echo "$certinfo"
    echo
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca-intermediate.pem\n${cfdir}/${d}-ca-intermediate-key.pem"
  fi
}

help_function() {
  echo
  echo "Usage:"
  #echo "$0 gen-all domain.com expiryhrs"
  echo
  echo "Generate CA certificate & keys"
  echo "$0 gen-ca domain.com expiryhrs"
  echo
  echo "Generate TLS server certificate & keys"
  echo "$0 gen-server domain.com expiryhrs server"
  echo
  echo "Generate TLS server wildcard certificate & keys"
  echo "$0 gen-server domain.com expiryhrs wildcard"
  echo
  echo "Generate TLS Client certificate & keys"
  echo "$0 gen-client domain.com expiryhrs client"
  echo
  echo "Generate TLS Peer certificate & keys"
  echo "$0 gen-peer domain.com expiryhrs peer"
  echo
  echo "Generate TLS Peer wildcard certificate & keys"
  echo "$0 gen-peer domain.com expiryhrs wildcard"
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
  gen-peer )
    peer_gen $2 $3 $4
    ;;
  reset )
    reset_dir
    ;;
  * )
    help_function
    ;;
esac