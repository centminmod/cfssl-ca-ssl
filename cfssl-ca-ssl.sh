#!/bin/bash
# for centminmod.com LEMP stack installations
ver=1.1
debug='y'
cfdir='/etc/cfssl'
cfcleanupdir="${cfdir}/cleanup"
servercerts_dir="${cfdir}/servercerts"
servercerts_selfsign_dir="${cfdir}/servercerts_selfsigned"
clientcerts_dir="${cfdir}/clientcerts"
peercerts_dir="${cfdir}/peercerts"
cfssl_bin='/root/golang/packages/bin/cfssl'
cfssljson_bin='/root/golang/packages/bin/cfssljson'
cfsslinfo_bin='/root/golang/packages/bin/cfssl-certinfo'
# cloudflare origin CA API
# set zid and xauth_user_service_key variables in
# persistent config file /etc/cfssl/cfssl.ini
zid=''
xauth_user_service_key=''
servercerts_cforigin_dir="${cfdir}/servercerts_cforigin"

if [ ! -d "$cfdir" ]; then
  mkdir -p "$cfdir"
fi
if [ ! -d "${cfcleanupdir}" ]; then
  mkdir -p "${cfcleanupdir}"
fi
if [ -f "$cfdir/cfssl.ini" ]; then
  source "$cfdir/cfssl.ini"
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
elif [[ ! -f "$cfssl_bin" || ! -f "$cfssljson_bin" || ! -f "$cfsslinfo_bin" ]] && [[ "$(go version >/dev/null 2>&1 && echo $?)" -eq '0' ]]; then
  go get -u github.com/cloudflare/cfssl/cmd/cfssl
  go get -u github.com/cloudflare/cfssl/cmd/cfssljson
  go get -u github.com/cloudflare/cfssl/cmd/cfssl-certinfo
  if [ -f "$cfssl_bin" ]; then
    cfssl version
  fi
fi
if [ ! "$(env | grep '/root/golang/packages/bin')" ] && [ -f /usr/local/src/centminmod/addons/golang.sh ]; then
  # ensure golang binary path is detected on first time golang.sh
  # installed SSH session
  export PATH=/root/golang/packages/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/lib64/ccache:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin:/usr/local/go/bin:/root/bin
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
  echo "{\"CN\":\"Root CA\",\"hosts\":[\"${domain}\",\"www.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"OU\":\"Root CA\",\"L\":\"San Francisco\"}],\"CA\":{\"expiry\":\"${expiry}h\",\"pathlen\":0}}" | jq > "${domain}-ca.csr.json"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "cfssl gencert -initca ${domain}-ca.csr.json | cfssljson -bare ${domain}-ca"
    echo
  fi
  cfssl gencert -initca "${domain}-ca.csr.json" | cfssljson -bare "${domain}-ca"
  if [[ "$debug" = [yY] ]]; then
    echo
    echo "openssl x509 -in ${cfdir}/${domain}-ca.pem -text -noout"
    echo
  fi
  echo "Extract CA Root certificate public key: ${cfdir}/${domain}-ca-publickey.pem"
  if [[ "$debug" = [yY] ]]; then
    echo "openssl x509 -pubkey -noout -in ${cfdir}/${domain}-ca.pem > ${cfdir}/${domain}-ca-publickey.pem"
    echo "cat ${cfdir}/${domain}-ca-publickey.pem"
  fi
  openssl x509 -pubkey -noout -in "${cfdir}/${domain}-ca.pem" > "${cfdir}/${domain}-ca-publickey.pem"
  echo
  cat "${cfdir}/${domain}-ca-publickey.pem"
  echo

  # check cert contents
  openssl x509 -in "${cfdir}/${domain}-ca.pem" -text -noout
  echo
  if [ -f "${cfdir}/${domain}-ca.pem" ]; then
    echo "ca cert: ${cfdir}/${domain}-ca.pem"
    certinfo=$(cfssl-certinfo -cert ${cfdir}/${domain}-ca.pem)
  fi
  if [ -f "${cfdir}/${domain}-ca-key.pem" ]; then
    chmod 0600 "${cfdir}/${domain}-ca-key.pem"
    echo "ca private key: ${cfdir}/${domain}-ca-key.pem"
  fi
  if [ -f "${cfdir}/${domain}-ca-publickey.pem" ]; then
    chmod 0600 "${cfdir}/${domain}-ca-publickey.pem"
    echo "ca public key: ${cfdir}/${domain}-ca-publickey.pem"
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
  echo "{\"CN\":\"Intermediate CA\",\"hosts\":[\"${domain}\",\"www.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"OU\":\"Intermediate CA\",\"L\":\"San Francisco\"}],\"CA\":{\"expiry\":\"${expiry}h\",\"pathlen\":0}}" | jq > "${domain}-ca-intermediate.csr.json"
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
  echo "Extract CA Intermediate certificate public key: ${cfdir}/${domain}-ca-intermediate-publickey.pem"
  if [[ "$debug" = [yY] ]]; then
    echo "openssl x509 -pubkey -noout -in ${cfdir}/${domain}-ca-intermediate.pem > ${cfdir}/${domain}-ca-intermediate-publickey.pem"
    echo "cat ${cfdir}/${domain}-ca-intermediate-publickey.pem"
  fi
  openssl x509 -pubkey -noout -in "${cfdir}/${domain}-ca-intermediate.pem" > "${cfdir}/${domain}-ca-intermediate-publickey.pem"
  echo
  cat "${cfdir}/${domain}-ca-intermediate-publickey.pem"
  echo

  # check cert contents
  openssl x509 -in "${cfdir}/${domain}-ca-intermediate.pem" -text -noout
  echo
  if [ -f "${cfdir}/${domain}-ca-intermediate.pem" ]; then
    echo "ca intermediate cert: ${cfdir}/${domain}-ca-intermediate.pem"
    certinfo=$(cfssl-certinfo -cert ${cfdir}/${domain}-ca-intermediate.pem)
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate-key.pem" ]; then
    chmod 0600 "${cfdir}/${domain}-ca-intermediate-key.pem"
    echo "ca intermediate private key: ${cfdir}/${domain}-ca-intermediate-key.pem"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate-publickey.pem" ]; then
    chmod 0600 "${cfdir}/${domain}-ca-intermediate-publickey.pem"
    echo "ca intermediate public key: ${cfdir}/${domain}-ca-intermediate-publickey.pem"
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

  # Cleanup create "${cfcleanupdir}/remove-ca-${domain}.sh"
  if [ -f "${cfdir}/${domain}-ca.pem" ]; then
    echo "rm -f ${cfdir}/${domain}-ca.pem" > "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca-key.pem" ]; then
    echo "rm -f ${cfdir}/${domain}-ca-key.pem" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca-publickey.pem" ]; then
    echo "rm -f ${cfdir}/${domain}-ca-publickey.pem" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca.csr" ]; then
    echo "rm -f ${cfdir}/${domain}-ca.csr" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca.csr.json" ]; then
    echo "rm -f ${cfdir}/${domain}-ca.csr.json" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/profile.json" ]; then
    echo "rm -f ${cfdir}/profile.json" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate.pem" ]; then
    echo "rm -f ${cfdir}/${domain}-ca-intermediate.pem" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate-key.pem" ]; then
    echo "rm -f ${cfdir}/${domain}-ca-intermediate-key.pem" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate-publickey.pem" ]; then
    echo "rm -f ${cfdir}/${domain}-ca-intermediate-publickey.pem" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate.csr" ]; then
    echo "rm -f ${cfdir}/${domain}-ca-intermediate.csr" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  if [ -f "${cfdir}/${domain}-ca-intermediate.csr.json" ]; then
    echo "rm -f ${cfdir}/${domain}-ca-intermediate.csr.json" >> "${cfcleanupdir}/remove-ca-${domain}.sh"
  fi
  chmod +x "${cfcleanupdir}/remove-ca-${domain}.sh"
  echo "Cleanup script created: ${cfcleanupdir}/remove-ca-${domain}.sh"
  echo "To clean up run: bash ${cfcleanupdir}/remove-ca-${domain}.sh"
}

server_gen() {
  d=${1:-centminmod.com}
  subdomain=${3:-server}
  sitedomain=${4:-centminmod.com}
  if [[ "$3" = 'wildcard' ]]; then
    serverdomain="$sitedomain"
    domain=${serverdomain}
  elif [[ "$3" = 'www' ]]; then
    serverdomain="${subdomain}.${sitedomain}"
    domain=${sitedomain}
  elif [ "$3" ]; then
    serverdomain="${subdomain}.${sitedomain}"
    domain=${serverdomain}
  else
    serverdomain="${sitedomain}"
    domain=${serverdomain}
  fi
  expiry=${2:-87600}
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca-intermediate.pem" && -f "${cfdir}/${d}-ca-intermediate-key.pem" ]]; then
    mkdir -p "${servercerts_dir}"
    cd "${servercerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    if [[ "$3" = 'wildcard' ]]; then
      echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"*.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile server -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}-ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile server \
            -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
            "${domain}.csr.json" > "${domain}.json"
    elif [[ "$3" = 'www' ]]; then
      echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"www.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"
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

    echo "Extract server certificate public key: ${servercerts_dir}/${domain}-publickey.pem"
    if [[ "$debug" = [yY] ]]; then
      echo "openssl x509 -pubkey -noout -in ${servercerts_dir}/${domain}.pem > ${servercerts_dir}/${domain}-publickey.pem"
      echo "cat ${servercerts_dir}/${domain}-publickey.pem"
    fi
    openssl x509 -pubkey -noout -in "${servercerts_dir}/${domain}.pem" > "${servercerts_dir}/${domain}-publickey.pem"
    echo
    cat "${servercerts_dir}/${domain}-publickey.pem"
    echo

    # check cert contents
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl x509 -in ${servercerts_dir}/${domain}.pem -text -noout"
      echo
    fi
    openssl x509 -in "${servercerts_dir}/${domain}.pem" -text -noout
    echo
    if [ -f "${servercerts_dir}/${domain}.pem" ]; then
      echo "server cert: ${servercerts_dir}/${domain}.pem"
      certinfo=$(cfssl-certinfo -cert ${servercerts_dir}/${domain}.pem)
    fi
    if [ -f "${servercerts_dir}/${domain}-key.pem" ]; then
      chmod 0600 "${servercerts_dir}/${domain}-key.pem"
      echo "server private key: ${servercerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${servercerts_dir}/${domain}-publickey.pem" ]; then
      chmod 0600 "${servercerts_dir}/${domain}-publickey.pem"
      echo "server public key: ${servercerts_dir}/${domain}-publickey.pem"
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
    echo "verify certificate"
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl verify -CAfile ${cfdir}/${d}-ca-bundle.pem ${servercerts_dir}/${domain}.pem"
    fi
    openssl verify -CAfile "${cfdir}/${d}-ca-bundle.pem" "${servercerts_dir}/${domain}.pem"
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca-intermediate.pem\n${cfdir}/${d}-ca-intermediate-key.pem"
  fi

  # clean up
  echo
  if [ -f "${servercerts_dir}/${domain}.pem" ]; then
    echo "rm -f ${servercerts_dir}/${domain}.pem" > "${cfcleanupdir}/remove-servercert-${domain}.sh"
  fi
  if [ -f "${servercerts_dir}/${domain}-key.pem" ]; then
    echo "rm -f ${servercerts_dir}/${domain}-key.pem" >> "${cfcleanupdir}/remove-servercert-${domain}.sh"
  fi
  if [ -f "${servercerts_dir}/${domain}-publickey.pem" ]; then
    echo "rm -f ${servercerts_dir}/${domain}-publickey.pem" >> "${cfcleanupdir}/remove-servercert-${domain}.sh"
  fi
  if [ -f "${servercerts_dir}/${domain}.csr" ]; then
    echo "rm -f ${servercerts_dir}/${domain}.csr" >> "${cfcleanupdir}/remove-servercert-${domain}.sh"
  fi
  if [ -f "${servercerts_dir}/${domain}.csr.json" ]; then
    echo "rm -f ${servercerts_dir}/${domain}.csr.json" >> "${cfcleanupdir}/remove-servercert-${domain}.sh"
  fi
  chmod +x "${cfcleanupdir}/remove-servercert-${domain}.sh"
  echo "Cleanup script created: ${cfcleanupdir}/remove-servercert-${domain}.sh"
  echo "To clean up run: bash ${cfcleanupdir}/remove-servercert-${domain}.sh"
}

client_gen() {
  d=${1:-centminmod.com}
  subdomain=${3:-client}
  sitedomain=${4:-centminmod.com}
  if [[ "$3" = 'wildcard' ]]; then
    clientdomain="$sitedomain"
    domain=${clientdomain}
  elif [[ "$3" = 'www' ]]; then
    clientdomain="${subdomain}.${sitedomain}"
    domain=${sitedomain}
  elif [[ "$3" ]]; then
    clientdomain="${subdomain}.${sitedomain}"
    domain=${clientdomain}
  else
    clientdomain="${sitedomain}"
    domain=${clientdomain}
  fi
  expiry=${2:-87600}
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca-intermediate.pem" && -f "${cfdir}/${d}-ca-intermediate-key.pem" ]]; then
    mkdir -p "${clientcerts_dir}"
    cd "${clientcerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    if [[ "$3" = 'wildcard' ]]; then
      echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"*.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile client -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}-ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile client \
            -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
            "${domain}.csr.json" > "${domain}.json"
    elif [[ "$3" = 'www' ]]; then
      echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"www.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile client -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}-ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile client \
            -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
            "${domain}.csr.json" > "${domain}.json"
    else
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile client -cn ${domain} -hostname ${domain} -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile client -cn "${domain}" -hostname "${domain}" \
          -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
          "${domain}.csr.json" > "${domain}.json"
    fi
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "cfssljson -f ${domain}.json -bare ${domain}"
      echo
    fi
    cfssljson -f "${domain}.json" -bare "${domain}"

    echo "Extract client certificate public key: ${clientcerts_dir}/${domain}-publickey.pem"
    if [[ "$debug" = [yY] ]]; then
      echo "openssl x509 -pubkey -noout -in ${clientcerts_dir}/${domain}.pem > ${clientcerts_dir}/${domain}-publickey.pem"
      echo "cat ${clientcerts_dir}/${domain}-publickey.pem"
    fi
    openssl x509 -pubkey -noout -in "${clientcerts_dir}/${domain}.pem" > "${clientcerts_dir}/${domain}-publickey.pem"
    echo
    cat "${clientcerts_dir}/${domain}-publickey.pem"
    echo

    # check cert contents
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl x509 -in ${clientcerts_dir}/${domain}.pem -text -noout"
      echo
    fi
    openssl x509 -in "${clientcerts_dir}/${domain}.pem" -text -noout
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
      echo "client private key: ${clientcerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${clientcerts_dir}/${domain}-publickey.pem" ]; then
      chmod 0600 "${clientcerts_dir}/${domain}-publickey.pem"
      echo "client public key: ${clientcerts_dir}/${domain}-publickey.pem"
    fi
    if [ -f "${clientcerts_dir}/${domain}.csr" ]; then
      echo "client csr: ${clientcerts_dir}/${domain}.csr"
    fi
    if [ -f "${clientcerts_dir}/${domain}.csr.json" ]; then
      echo "client csr profile: ${clientcerts_dir}/${domain}.csr.json"
    fi
    if [[ -f "${clientcerts_dir}/${domain}.pem" && -f "${cfdir}/${d}-ca-bundle.pem" ]]; then
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "Generate ${clientcerts_dir}/${domain}-client-bundle.pem"
        echo "cat ${clientcerts_dir}/${domain}.pem ${cfdir}/${d}-ca-bundle.pem > ${clientcerts_dir}/${domain}-client-bundle.pem"
      fi
      cat "${clientcerts_dir}/${domain}.pem" "${cfdir}/${d}-ca-bundle.pem" > "${clientcerts_dir}/${domain}-client-bundle.pem"
      echo "client bundle chain: ${clientcerts_dir}/${domain}-client-bundle.pem"
      echo
    fi
    echo
    echo "Check certificate purpose:"
    echo "openssl x509 -in ${clientcerts_dir}/${domain}.pem -noout -purpose"
    openssl x509 -in "${clientcerts_dir}/${domain}.pem" -noout -purpose
    echo
    echo "$certinfo"
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl verify -CAfile ${cfdir}/${d}-ca-bundle.pem ${clientcerts_dir}/${domain}.pem"
    fi
    openssl verify -CAfile "${cfdir}/${d}-ca-bundle.pem" "${clientcerts_dir}/${domain}.pem"
    echo
    echo "---------------------------------------------------------------------------"
    echo "For Cloudflare Enterprise custom Authenticated Origin Pull Client Certificate API Upload"
    echo "---------------------------------------------------------------------------"
    echo "- https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/#per-hostname--customer-certificates"
    echo "- https://api.cloudflare.com/#per-hostname-authenticated-origin-pull-upload-a-hostname-client-certificate"
    echo
    echo "populate variables"
    echo
    #echo "MYCERT=\$(cat ${clientcerts_dir}/${domain}.pem |perl -pe 's/\r?\n/\\\n/'|sed -e 's/..$//')"
    echo "MYCERT=\$(cfssl-certinfo -cert ${clientcerts_dir}/${domain}.pem | jq '.pem' | sed -e 's|\"||g')"
    echo "MYKEY=\$(cat ${clientcerts_dir}/${domain}-key.pem | perl -pe 's/\r?\n/\\\n/'|sed -e's/..$//')"
    echo "request_body='$(echo "{ "\"certificate"\": "\"\$MYCERT"\", "\"private_key"\": "\"\$MYKEY"\" }")' " | sed -e 's|\"|\\"|g' -e "s|'|\"|g"
    echo
    echo "export cfzoneid=cf_zone_id"
    echo "export cfemail=cf_account_email"
    echo "export cftoken=cf_account_global_api_keytoken"
    echo "export cf_hostname=domain_name_on_ssl_certificate"
    echo
    echo "---------------------------------------------------------------------------"
    echo "Upload TLS client certificate via CF API"
    echo "---------------------------------------------------------------------------"
    echo
    echo "For custom hostname/subdomains i.e. hostname.domain.com or subdomain.domain.com"
    echo "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/#per-hostname--customer-certificates"
    echo
    echo "curl -sX POST https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/hostnames/certificates -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \"\$request_body\" | jq | tee ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload.txt"
    echo
    echo "Or for apex non-subdomains i.e. domain.com"
    echo "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/#zone-level--customer-certificates"
    echo
    echo "curl -sX POST https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \"\$request_body\" | jq | tee ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload.txt"
    echo
    echo "export clientcert_id=\$(jq -r '.result.id' ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload.txt)"
    echo "echo \"\$clientcert_id\" > ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-clientcert-id.txt"
    echo
    echo "---------------------------------------------------------------------------"
    echo "Check uploaded TLS client certificate via CF API"
    echo "---------------------------------------------------------------------------"
    echo
    echo "For custom hostname/subdomains i.e. hostname.domain.com or subdomain.domain.com"
    echo "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/#per-hostname--customer-certificates"
    echo
    echo "curl -sX GET \"https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/hostnames/certificates/\$clientcert_id\" -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \"\$request_body\" | jq | tee ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-status.txt"
    echo
    echo "Or for apex non-subdomains i.e. domain.com"
    echo "https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/#zone-level--customer-certificates"
    echo
    echo "curl -sX GET \"https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/\$clientcert_id\" -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \"\$request_body\" | jq | tee ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-status.txt"
    echo
    echo "---------------------------------------------------------------------------"
    echo "To delete uploaded TLS client certificate via CF API"
    echo "---------------------------------------------------------------------------"
    echo
    echo "For custom hostname/subdomains i.e. hostname.domain.com or subdomain.domain.com"
    echo "curl -sX DELETE \"https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/hostnames/certificates/\$clientcert_id\" -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \"\$request_body\" | jq | tee ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-delete.txt"
    echo
    echo "Or for apex non-subdomains i.e. domain.com"
    echo "curl -sX DELETE \"https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/\$clientcert_id\" -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \"\$request_body\" | jq | tee ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-delete.txt"
    echo
    echo "---------------------------------------------------------------------------"
    echo "Enable specific hostname Authenticated Origin Pull via Cloudflare API"
    echo "---------------------------------------------------------------------------"
    echo
    echo "For custom hostname/subdomains i.e. hostname.domain.com or subdomain.domain.com"
    echo "curl -sX PUT https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/hostnames -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \$(jq -c -n --arg cf_hostname \$cf_hostname --arg clientcert_id \$clientcert_id \$(echo \"{\\\"config\\\":[{\\\"hostname\\\":\\\"\$cf_hostname\\\",\\\"cert_id\\\":\\\"\$clientcert_id\\\",\\\"enabled\\\":true}]}\")) | jq"
    echo
    echo "Or for apex non-subdomains i.e. domain.com"
    echo "curl -sX PUT https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/settings -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d '{\"enabled\":true}' | jq"
    echo
    echo "---------------------------------------------------------------------------"
    echo "Disable specific hostname Authenticated Origin Pull via Cloudflare API"
    echo "---------------------------------------------------------------------------"
    echo
    echo "For custom hostname/subdomains i.e. hostname.domain.com or subdomain.domain.com"
    echo "curl -sX PUT https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/hostnames -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d \$(jq -c -n --arg cf_hostname \$cf_hostname --arg clientcert_id \$clientcert_id \$(echo \"{\\\"config\\\":[{\\\"hostname\\\":\\\"\$cf_hostname\\\",\\\"cert_id\\\":\\\"\$clientcert_id\\\",\\\"enabled\\\":false}]}\")) | jq"
    echo
    echo "Or for apex non-subdomains i.e. domain.com"
    echo "curl -sX PUT https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/settings -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" -d '{\"enabled\":false}' | jq"
    echo
    echo "---------------------------------------------------------------------------"
    echo "Check CF Status for specific hostname Authenticated Origin Pull via Cloudflare API"
    echo "---------------------------------------------------------------------------"
    echo
    echo "For custom hostname/subdomains i.e. hostname.domain.com or subdomain.domain.com"
    echo "curl -sX GET \"https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/hostnames/\$cf_hostname\" -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" | jq"
    echo
    echo "Or for apex non-subdomains i.e. domain.com"
    echo "curl -sX GET \"https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth/settings\" -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" | jq"
    echo
    echo "---------------------------------------------------------------------------"
    echo "List uploaded Origin TLS Client Authenticatied Certificates"
    echo "---------------------------------------------------------------------------"
    echo
    echo "curl -sX GET \"https://api.cloudflare.com/client/v4/zones/\$cfzoneid/origin_tls_client_auth\" -H \"X-Auth-Email: \$cfemail\" -H \"X-Auth-Key: \$cftoken\" -H \"Content-Type: application/json\" | jq"
    echo
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca-intermediate.pem\n${cfdir}/${d}-ca-intermediate-key.pem"
  fi
  # cleanup
  echo
  if [ -f "${clientcerts_dir}/${domain}.p12" ]; then
    echo "rm -f ${clientcerts_dir}/${domain}.p12" > "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}.pem" ]; then
    echo "rm -f ${clientcerts_dir}/${domain}.pem" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}-key.pem" ]; then
    echo "rm -f ${clientcerts_dir}/${domain}-key.pem" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}-publickey.pem" ]; then
    echo "rm -f ${clientcerts_dir}/${domain}-publickey.pem" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}.csr" ]; then
    echo "rm -f ${clientcerts_dir}/${domain}.csr" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}.csr.json" ]; then
    echo "rm -f ${clientcerts_dir}/${domain}.csr.json" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}-client-bundle.pem" ]; then
    echo "rm -f ${clientcerts_dir}/${domain}-client-bundle.pem" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload.txt" ]; then
    echo "rf -f ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload.txt" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-clientcert-id.txt" ]; then
    echo "rf -f ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-clientcert-id.txt" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-status.txt" ]; then
    echo "rf -f ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-status.txt" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  if [ -f "${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-delete.txt" ]; then
    echo "rf -f ${clientcerts_dir}/${domain}-cf-origin-tls-cleint-auth-cert-upload-delete.txt" >> "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  fi
  chmod +x "${cfcleanupdir}/remove-clientcert-${domain}.sh"
  echo "Cleanup script created: ${cfcleanupdir}/remove-clientcert-${domain}.sh"
  echo "To clean up run: bash ${cfcleanupdir}/remove-clientcert-${domain}.sh"
}

peer_gen() {
  d=${1:-centminmod.com}
  subdomain=${3:-server}
  sitedomain=${4:-centminmod.com}
  if [[ "$3" = 'wildcard' ]]; then
    peerdomain="$sitedomain"
    domain=${peerdomain}
  elif [[ "$3" = 'www' ]]; then
    peerdomain="${subdomain}.${sitedomain}"
    domain=${sitedomain}
  elif [ "$3" ]; then
    peerdomain="${subdomain}.${sitedomain}"
    domain=${peerdomain}
  else
    peerdomain="${sitedomain}"
    domain=${peerdomain}
  fi
  expiry=${2:-87600}
  if [[ -f "${cfdir}/profile.json" && -f "${cfdir}/${d}-ca-intermediate.pem" && -f "${cfdir}/${d}-ca-intermediate-key.pem" ]]; then
    mkdir -p "${peercerts_dir}"
    cd "${peercerts_dir}"
    cfssl print-defaults csr | jq 'del(.CN, .hosts)' > "${domain}.csr.json"
    if [[ "$3" = 'wildcard' ]]; then
      echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"*.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"

      if [[ "$debug" = [yY] ]]; then
        echo
        echo "cfssl gencert -config ${cfdir}/profile.json -profile peer -ca ${cfdir}/${d}-ca-intermediate.pem -ca-key ${cfdir}/${d}-ca-intermediate-key.pem ${domain}.csr.json > ${domain}.json"
      fi
      cfssl gencert -config "${cfdir}/profile.json" -profile peer \
            -ca "${cfdir}/${d}-ca-intermediate.pem" -ca-key "${cfdir}/${d}-ca-intermediate-key.pem" \
            "${domain}.csr.json" > "${domain}.json"
    elif [[ "$3" = 'www' ]]; then
      echo "{\"CN\":\"${domain}\",\"hosts\":[\"${domain}\",\"www.${domain}\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"ST\":\"CA\",\"L\":\"San Francisco\"}]}" | jq > "${domain}.csr.json"

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

    echo "Extract peer certificate public key: ${peercerts_dir}/${domain}-publickey.pem"
    if [[ "$debug" = [yY] ]]; then
      echo "openssl x509 -pubkey -noout -in ${peercerts_dir}/${domain}.pem > ${peercerts_dir}/${domain}-publickey.pem"
      echo "cat ${peercerts_dir}/${domain}-publickey.pem"
    fi
    openssl x509 -pubkey -noout -in "${peercerts_dir}/${domain}.pem" > "${peercerts_dir}/${domain}-publickey.pem"
    echo
    cat "${peercerts_dir}/${domain}-publickey.pem"
    echo

    # check cert contents
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl x509 -in ${peercerts_dir}/${domain}.pem -text -noout"
      echo
    fi
    openssl x509 -in "${peercerts_dir}/${domain}.pem" -text -noout
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
      echo "peer private key: ${peercerts_dir}/${domain}-key.pem"
    fi
    if [ -f "${peercerts_dir}/${domain}-publickey.pem" ]; then
      chmod 0600 "${peercerts_dir}/${domain}-publickey.pem"
      echo "peer public key: ${peercerts_dir}/${domain}-publickey.pem"
    fi
    if [ -f "${peercerts_dir}/${domain}.csr" ]; then
      echo "peer csr: ${peercerts_dir}/${domain}.csr"
    fi
    if [ -f "${peercerts_dir}/${domain}.csr.json" ]; then
      echo "peer csr profile: ${peercerts_dir}/${domain}.csr.json"
    fi
    if [[ -f "${peercerts_dir}/${domain}.pem" && -f "${cfdir}/${d}-ca-bundle.pem" ]]; then
      if [[ "$debug" = [yY] ]]; then
        echo
        echo "Generate ${peercerts_dir}/${domain}-peer-bundle.pem"
        echo "cat ${peercerts_dir}/${domain}.pem ${cfdir}/${d}-ca-bundle.pem > ${peercerts_dir}/${domain}-peer-bundle.pem"
      fi
      cat "${peercerts_dir}/${domain}.pem" "${cfdir}/${d}-ca-bundle.pem" > "${peercerts_dir}/${domain}-peer-bundle.pem"
      echo "peer bundle chain: ${clientcerts_dir}/${domain}-client-bundle.pem"
      echo
    fi
    echo
    echo "Check certificate purpose:"
    echo "openssl x509 -in ${peercerts_dir}/${domain}.pem -noout -purpose"
    openssl x509 -in "${peercerts_dir}/${domain}.pem" -noout -purpose
    echo
    echo "$certinfo"
    if [[ "$debug" = [yY] ]]; then
      echo
      echo "openssl verify -CAfile ${cfdir}/${d}-ca-bundle.pem ${peercerts_dir}/${domain}.pem"
    fi
    openssl verify -CAfile "${cfdir}/${d}-ca-bundle.pem" "${peercerts_dir}/${domain}.pem"
    echo
  else
    echo "error: missing required files:"
    echo -e "${cfdir}/profile.json\n${cfdir}/${d}-ca-intermediate.pem\n${cfdir}/${d}-ca-intermediate-key.pem"
  fi

  # cleanup
  echo
    if [ -f "${peercerts_dir}/${domain}.p12" ]; then
        echo "rm -f ${peercerts_dir}/${domain}.p12" > "${cfcleanupdir}/remove-peercert-${domain}.sh"
    fi
    if [ -f "${peercerts_dir}/${domain}.pem" ]; then
      echo "rm -f ${peercerts_dir}/${domain}.pem" >> "${cfcleanupdir}/remove-peercert-${domain}.sh"
    fi
    if [ -f "${peercerts_dir}/${domain}-key.pem" ]; then
      echo "rm -f ${peercerts_dir}/${domain}-key.pem" >> "${cfcleanupdir}/remove-peercert-${domain}.sh"
    fi
    if [ -f "${peercerts_dir}/${domain}-publickey.pem" ]; then
      echo "rm -f ${peercerts_dir}/${domain}-publickey.pem" >> "${cfcleanupdir}/remove-peercert-${domain}.sh"
    fi
    if [ -f "${peercerts_dir}/${domain}.csr" ]; then
      echo "rm -f ${peercerts_dir}/${domain}.csr" >> "${cfcleanupdir}/remove-peercert-${domain}.sh"
    fi
    if [ -f "${peercerts_dir}/${domain}.csr.json" ]; then
      echo "rm -f ${peercerts_dir}/${domain}.csr.json" >> "${cfcleanupdir}/remove-peercert-${domain}.sh"
    fi
    if [ -f "${clientcerts_dir}/${domain}-client-bundle.pem" ]; then
      echo "rm -f ${clientcerts_dir}/${domain}-client-bundle.pem" >> "${cfcleanupdir}/remove-peercert-${domain}.sh"
    fi
  chmod +x "${cfcleanupdir}/remove-peercert-${domain}.sh"
  echo "Cleanup script created: ${cfcleanupdir}/remove-peercert-${domain}.sh"
  echo "To clean up run: bash ${cfcleanupdir}/remove-peercert-${domain}.sh"
}

selfsign_gen() {
  mkdir -p "$servercerts_selfsign_dir"
  cd "$servercerts_selfsign_dir"
  d="$1"
  expiry=${2:-87600}
  type=${3:-ecc}
  org=org
  orgu=orgu
  if [[ "type" = 'ecc' ]]; then
    algo_input=ecdsa
    algo_length=256
  else
    algo_input=rsa
    algo_length=2048
  fi
  # create generic profile.json
  echo "{\"signing\":{\"default\":{\"expiry\":\"8760h\"},\"profiles\":{\"intermediate_ca\":{\"usages\":[\"signing\",\"digital signature\",\"key encipherment\",\"cert sign\",\"crl sign\",\"server auth\",\"client auth\"],\"expiry\":\"8760h\",\"ca_constraint\":{\"is_ca\":true,\"max_path_len\":0,\"max_path_len_zero\":true}},\"peer\":{\"usages\":[\"signing\",\"digital signature\",\"key encipherment\",\"client auth\",\"server auth\"],\"expiry\":\"8760h\"},\"server\":{\"usages\":[\"signing\",\"digital signing\",\"key encipherment\",\"server auth\"],\"expiry\":\"8760h\"},\"client\":{\"usages\":[\"signing\",\"digital signature\",\"key encipherment\",\"client auth\"],\"expiry\":\"8760h\"}}}}" | jq | sed -e "s|8760h|${expiry}h|g" -e "s|168h|${expiry}h|g" > "$servercerts_selfsign_dir/profile.json"
  # create csr.json
  echo "-----------------------------------------------------------------"
  echo "create $servercerts_selfsign_dir/$d-csr.json"
  echo "-----------------------------------------------------------------"
  echo "{\"CN\": \"$d\",\"hosts\":[\"*.$d\",\"$d\"],\"key\":{\"algo\":\"$algo_input\",\"size\":$algo_length},\"names\":[{\"C\":\"US\",\"L\":\"San Francisco\",\"O\":\"$org\",\"OU\":\"$orgu\",\"ST\":\"California\"}]}" | jq -r > "$servercerts_selfsign_dir/$d-csr.json"
  # # create private key & csr
  # echo
  # echo "-----------------------------------------------------------------"
  # echo "create $d-cert.csr + $d-cert-key.pem"
  # echo "-----------------------------------------------------------------"
  # echo "cfssl genkey $servercerts_selfsign_dir/$d-csr.json | cfssljson -bare"
  # cfssl genkey "$servercerts_selfsign_dir/$d-csr.json" | cfssljson -bare
  # mv cert.csr "$d-cert.csr"
  # mv cert-key.pem "$d-cert-key.pem"
  # create selfsigned SSL certificate
  echo
  echo "-----------------------------------------------------------------"
  echo "create selfsigned SSL certificate $d-cert.pem"
  echo "-----------------------------------------------------------------"
  echo "cfssl selfsign -config $servercerts_selfsign_dir/profile.json -profile server -hostname=*.$d,$d $servercerts_selfsign_dir/$d-csr.json | cfssljson -bare"
  cfssl selfsign -config "$servercerts_selfsign_dir/profile.json" -profile server -hostname=*.$d,$d "$servercerts_selfsign_dir/$d-csr.json" | cfssljson -bare
  mv cert.pem "$d-cert.pem"
  mv cert.csr "$d-cert.csr"
  mv cert-key.pem "$d-cert-key.pem"
  # get cert.pem info
  echo
  echo "-----------------------------------------------------------------"
  echo "inspect $d-cert.pem"
  echo "-----------------------------------------------------------------"
  echo "cfssl-certinfo -cert $servercerts_selfsign_dir/$d-cert.pem"
  cfssl-certinfo -cert "$servercerts_selfsign_dir/$d-cert.pem"
  echo
  echo "openssl x509 -in $servercerts_selfsign_dir/$d-cert.pem -text -noout"
  openssl x509 -in "$servercerts_selfsign_dir/$d-cert.pem" -text -noout
  echo
  echo "-----------------------------------------------------------------"
  echo "JSON format $d-cert.pem, $d-cert-key.pem & $d-cert.csr"
  echo "-----------------------------------------------------------------"
  echo "cfssl-certinfo -cert $servercerts_selfsign_dir/$d-cert.pem | jq '.pem' | sed -e 's|\"||g'"
  echo
  cfssl-certinfo -cert $servercerts_selfsign_dir/$d-cert.pem | jq '.pem' | sed -e 's|"||g'
  echo
  echo "cat $servercerts_selfsign_dir/$d-cert-key.pem | perl -pe 's/\\r?\n/\\\n/'|sed -e's/..\$//'"
  echo
  cat $servercerts_selfsign_dir/$d-cert-key.pem | perl -pe 's/\r?\n/\\n/'|sed -e's/..$//'
  echo
  echo
  echo "cat $servercerts_selfsign_dir/$d-cert.csr | perl -pe 's/\\r?\n/\\\n/'|sed -e's/..\$//'"
  echo
  cat $servercerts_selfsign_dir/$d-cert.csr | perl -pe 's/\r?\n/\\n/'|sed -e's/..$//'
  echo
  echo "-----------------------------------------------------------------"
  echo "Created selfsigned SSL wildcard certificate for $domain"
  echo "-----------------------------------------------------------------"
  ls -lhArt $servercerts_selfsign_dir
  echo
  echo "-----------------------------------------------------------------"
  echo "Nginx configuration"
  echo "-----------------------------------------------------------------"
  echo "ssl_certificate     $servercerts_selfsign_dir/$d-cert.pem;"
  echo "ssl_certificate_key $servercerts_selfsign_dir/$d-cert-key.pem;"
  echo
}

cforigin_list() {
  ZONEID=$1
  if [ -z "$ZONEID" ]; then
    zid=$zid
  elif [ "$ZONEID" ]; then
    zid=$ZONEID
  fi
  CFAPI='https://api.cloudflare.com/client/v4'
  CFAPI_ENDPOINT="certificates?zone_id=$zid&page=1&per_page=200"
  # sort by expiry date ascending
  echo "curl -4sX GET \"${CFAPI}/certificates?zone_id=\$zid&page=1&per_page=200\" -H \"X-Auth-User-Service-Key: \$xauth_user_service_key\" | jq -r '.result | sort_by(.expires_on)'"
  curl -4sX GET "${CFAPI}/${CFAPI_ENDPOINT}" \
     -H "X-Auth-User-Service-Key: $xauth_user_service_key" | jq -r '.result | sort_by(.expires_on)'
}

cforigin_create() {
  DOMAIN=$1
  ZONEID=$2
  org=org
  orgu=orgu
  mkdir -p "$servercerts_cforigin_dir"
  cd "$servercerts_cforigin_dir"
  if [ -z "$ZONEID" ]; then
    zid=$zid
  elif [ "$ZONEID" ]; then
    zid=$ZONEID
  fi
  CFAPI='https://api.cloudflare.com/client/v4'
  CFAPI_ENDPOINT="certificates?zone_id=$zid&page=1&per_page=200"
  
  # Generate CSR and private key
  echo
  echo "-----------------------------------------------------------------"
  echo "Generate CSR & private key"
  echo "-----------------------------------------------------------------"
  echo "{\"CN\": \"$DOMAIN\",\"hosts\":[\"*.$DOMAIN\",\"$DOMAIN\"],\"key\":{\"algo\":\"ecdsa\",\"size\":256},\"names\":[{\"C\":\"US\",\"L\":\"San Francisco\",\"O\":\"$org\",\"OU\":\"$orgu\",\"ST\":\"California\"}]}" | jq -r | tee "${servercerts_cforigin_dir}/cfca-origin-csr-${DOMAIN}.json"
  cfssl genkey "${servercerts_cforigin_dir}/cfca-origin-csr-${DOMAIN}.json" | cfssljson -bare
  mv cert.csr "$DOMAIN-cert.csr"
  mv cert-key.pem "$DOMAIN-cert-key.pem"
  CSR_CERT_JSON=$(cat ${servercerts_cforigin_dir}/$DOMAIN-cert.csr | perl -pe 's/\r?\n/\\n/'|sed -e's/..$//')
  CSR_PAYLOAD="{\"hostnames\":[\"$DOMAIN\",\"*.$DOMAIN\"],\"requested_validity\":5475,\"request_type\":\"origin-ecc\",\"csr\":\"$CSR_CERT_JSON\"}"
  echo "created CSR ${servercerts_cforigin_dir}/$DOMAIN-cert.csr"
  echo "created Private Key ${servercerts_cforigin_dir}/$DOMAIN-cert-key.pem"

  echo
  echo "-----------------------------------------------------------------"
  echo "Get Cloudflare Origin Certificate Using Generated CSR"
  echo "-----------------------------------------------------------------"
  echo "curl -4sX POST \"${CFAPI}/certificates?zone_id=\$zid&page=1&per_page=200\" -H \"X-Auth-User-Service-Key: \$xauth_user_service_key\" --data \"$CSR_PAYLOAD\""
  echo
  curl -4sX POST "${CFAPI}/${CFAPI_ENDPOINT}" \
     -H "X-Auth-User-Service-Key: $xauth_user_service_key" --data "$CSR_PAYLOAD" | jq -r | tee "${servercerts_cforigin_dir}/cfca-origin-cert-${DOMAIN}.json"

  echo
  echo "-----------------------------------------------------------------"
  echo "Inspect ${servercerts_cforigin_dir}/cfca-origin-cert-${DOMAIN}.json"
  echo "-----------------------------------------------------------------"
  cat "${servercerts_cforigin_dir}/cfca-origin-cert-${DOMAIN}.json" | jq -r '.result.certificate' | tee "${servercerts_cforigin_dir}/${DOMAIN}-cert.pem"
  echo "created CF Origin SSL certificate ${servercerts_cforigin_dir}/${DOMAIN}-cert.pem"

  echo
  echo "-----------------------------------------------------------------"
  echo "cfssl-certinfo -cert ${servercerts_cforigin_dir}/${DOMAIN}-cert.pem"
  echo "-----------------------------------------------------------------"
  cfssl-certinfo -cert "${servercerts_cforigin_dir}/${DOMAIN}-cert.pem"

  echo
  echo "Get Cloudflare Origina CA Root ECC Certificate"
  wget -4 -q -O "${servercerts_cforigin_dir}/origin_ca_ecc_root.pem" https://developers.cloudflare.com/ssl/static/origin_ca_ecc_root.pem

  # build fullchain.pem
  cat "${servercerts_cforigin_dir}/${DOMAIN}-cert.pem" "${servercerts_cforigin_dir}/origin_ca_ecc_root.pem" > "${servercerts_cforigin_dir}/${DOMAIN}-fullchain.pem"

  echo
  ls -lAhrt "${servercerts_cforigin_dir}"

  echo
  echo "CSR: ${servercerts_cforigin_dir}/$DOMAIN-cert.csr"
  echo "Private Key: ${servercerts_cforigin_dir}/$DOMAIN-cert-key.pem"
  echo "CF Origin SSL certificate: ${servercerts_cforigin_dir}/${DOMAIN}-cert.pem"
  echo "CF Origina CA Root certificate: ${servercerts_cforigin_dir}/origin_ca_ecc_root.pem"
  echo "CF Origin SSL certificate fullchain: ${servercerts_cforigin_dir}/${DOMAIN}-fullchain.pem"
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
  echo "$0 gen-server ca-domain.com expiryhrs server sitedomain.com"
  echo
  echo "Generate TLS server wildcard certificate & keys"
  echo "$0 gen-server ca-domain.com expiryhrs wildcard sitedomain.com"
  echo
  echo "Generate TLS Client certificate & keys"
  echo "$0 gen-client ca-domain.com expiryhrs client sitedomain.com"
  echo
  echo "Generate TLS Peer certificate & keys"
  echo "$0 gen-peer ca-domain.com expiryhrs peer sitedomain.com"
  echo
  echo "Generate TLS Peer wildcard certificate & keys"
  echo "$0 gen-peer ca-domain.com expiryhrs wildcard sitedomain.com"
  echo
  echo "Generate Selfsigned TLS server wildcard certificate, keys and csr files"
  echo "$0 selfsign domain.com expiryhrs ecc|rsa"
  echo
  echo "Cloudflare Origin CA Certificate List configured in /etc/cfssl/cfssl.ini"
  echo "$0 cforigin-cert-list"
  echo "$0 cforigin-cert-list zoneid"
  echo
  echo "Create Cloudflare Origin CA Certificate"
  echo "$0 cforigin-create domain.com"
  echo "$0 cforigin-create domain.com zoneid"
}

case "$1" in
  gen-all )
    ca_gen $2 $3
    server_gen $2 $3 $4 $5
    client_gen $2 $3 $4 $5
    ;;
  gen-ca )
    ca_gen $2 $3
    ;;
  gen-server )
    server_gen $2 $3 $4 $5
    ;;
  gen-client )
    client_gen $2 $3 $4 $5
    ;;
  gen-peer )
    peer_gen $2 $3 $4 $5
    ;;
  selfsign )
    selfsign_gen $2 $3 $4
    ;;
  reset )
    reset_dir
    ;;
  cforigin-cert-list )
    cforigin_list $2
    ;;
  cforigin-create )
    cforigin_create $2 $3
    ;;
  * )
    help_function
    ;;
esac