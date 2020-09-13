Using [cfssl](https://github.com/cloudflare/cfssl) to generate a CA certificate/key and to sign server, client and peer self-signed SSL certificates with it. Mainly intended for [Centmin Mod LEMP stack](https://centminmod.com) installations on CentOS 7.x for creating Nginx based TLS/SSL client certificate authentication via [ssl_client_certificate](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate) and [ssl_verify_client](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) directives using [gen-client option](#client-ssl-certificate).

# cfssl-ca-ssl.sh Contents


* [Usage](#usage)
* [CA Certificate](#ca-certificate)
* [Server Wildcard SSL Certificate](#server-wildcard-ssl-certificate)
* [Server SSL Certificate](#server-ssl-certificate)
* [Client SSL Certificate](#client-ssl-certificate)
* [Peer Wildcard SSL Certificate](#peer-wildcard-ssl-certificate)
* [Peer SSL Certificate](#peer-wildcard-ssl-certificate)
* [Nginx Configuration](#nginx-configuration)
* [Browser Client TLS Authentication](#browser-client-tls-authentication)
* [Curl Client TLS Authentication](#curl-client-tls-authentication)

# Usage

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh

Usage:

Generate CA certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca domain.com expiryhrs

Generate TLS server certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server ca-domain.com expiryhrs server sitedomain.com

Generate TLS server wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server ca-domain.com expiryhrs wildcard sitedomain.com

Generate TLS Client certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client ca-domain.com expiryhrs client sitedomain.com

Generate TLS Peer certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer ca-domain.com expiryhrs peer sitedomain.com

Generate TLS Peer wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer ca-domain.com expiryhrs wildcard sitedomain.com
```

# CA Certificate

Generate CA & CA Intermediate signed certificates for centminmod.com with 87600 hrs expiry = 10yrs with:

* CA certificate /etc/cfssl/centminmod.com-ca.pem
* CA Intermediate certificate /etc/cfssl/centminmod.com-ca-intermediate.pem
* CA Bundle certificate /etc/cfssl/centminmod.com-ca-bundle.pem

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca centminmod.com 87600
--------------------------------------
CA generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca.csr.json | cfssljson -bare centminmod.com-ca

2020/09/13 07:45:25 [INFO] generating a new CA key and certificate from CSR
2020/09/13 07:45:25 [INFO] generate received request
2020/09/13 07:45:25 [INFO] received CSR
2020/09/13 07:45:25 [INFO] generating key: ecdsa-256
2020/09/13 07:45:25 [INFO] encoded CSR
2020/09/13 07:45:25 [INFO] signed certificate with serial number 634967103701624269021989158899568926308647337040

openssl x509 -in centminmod.com-ca.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6f:38:e8:e0:65:eb:58:4c:bf:b3:8b:f9:b8:59:0b:56:22:38:7c:50
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=Root CA
        Validity
            Not Before: Sep 13 07:40:00 2020 GMT
            Not After : Sep 11 07:40:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:29:64:57:a9:f9:5a:fc:33:dc:c4:b5:4b:69:fe:
                    8f:e1:c2:87:ce:d8:47:d7:42:09:e6:90:78:92:be:
                    a2:00:3c:c3:d8:00:89:5b:7c:fc:24:e6:98:b5:4e:
                    cd:fe:6e:25:1c:22:5f:67:4c:93:84:45:bb:17:11:
                    67:33:8c:70:05
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                8C:26:8E:C6:7E:48:E7:98:3B:85:A9:CD:A4:6F:1D:B3:C4:7C:FC:25
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:0a:cc:b1:b0:e3:62:6f:58:3d:5e:ff:53:f4:d6:
         62:f9:71:58:4a:84:3f:b9:79:f0:f3:bb:81:6a:84:61:b9:67:
         02:20:5d:14:7e:74:c9:98:cf:8d:dd:2c:fa:b0:c6:52:3e:84:
         0e:5f:e6:69:fa:fc:a1:48:a9:16:75:0f:4e:ae:8d:c4

ca cert: /etc/cfssl/centminmod.com-ca.pem
ca key: /etc/cfssl/centminmod.com-ca-key.pem
ca csr: /etc/cfssl/centminmod.com-ca.csr
ca csr profile: /etc/cfssl/centminmod.com-ca.csr.json
ca profile: /etc/cfssl/profile.json

{
  "subject": {
    "common_name": "Root CA",
    "country": "US",
    "organizational_unit": "Root CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Root CA",
      "Root CA"
    ]
  },
  "issuer": {
    "common_name": "Root CA",
    "country": "US",
    "organizational_unit": "Root CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Root CA",
      "Root CA"
    ]
  },
  "serial_number": "634967103701624269021989158899568926308647337040",
  "not_before": "2020-09-13T07:40:00Z",
  "not_after": "2030-09-11T07:40:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "8C:26:8E:C6:7E:48:E7:98:3B:85:A9:CD:A4:6F:1D:B3:C4:7C:FC:25",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB7zCCAZagAwIBAgIUbzjo4GXrWEy/s4v5uFkLViI4fFAwCgYIKoZIzj0EAwIw\nVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRAwDgYDVQQLEwdSb290IENBMRAwDgYDVQQDEwdSb290IENBMB4XDTIwMDkx\nMzA3NDAwMFoXDTMwMDkxMTA3NDAwMFowVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgT\nAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRAwDgYDVQQLEwdSb290IENBMRAw\nDgYDVQQDEwdSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKWRXqfla\n/DPcxLVLaf6P4cKHzthH10IJ5pB4kr6iADzD2ACJW3z8JOaYtU7N/m4lHCJfZ0yT\nhEW7FxFnM4xwBaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w\nHQYDVR0OBBYEFIwmjsZ+SOeYO4WpzaRvHbPEfPwlMAoGCCqGSM49BAMCA0cAMEQC\nIArMsbDjYm9YPV7/U/TWYvlxWEqEP7l58PO7gWqEYblnAiBdFH50yZjPjd0s+rDG\nUj6EDl/mafr8oUipFnUPTq6NxA==\n-----END CERTIFICATE-----\n"
}

--------------------------------------
CA Intermediate generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca-intermediate.csr.json | cfssljson -bare centminmod.com-ca-intermediate

2020/09/13 07:45:25 [INFO] generating a new CA key and certificate from CSR
2020/09/13 07:45:25 [INFO] generate received request
2020/09/13 07:45:25 [INFO] received CSR
2020/09/13 07:45:25 [INFO] generating key: ecdsa-256
2020/09/13 07:45:25 [INFO] encoded CSR
2020/09/13 07:45:25 [INFO] signed certificate with serial number 291931583471547756428097462447970605582909747146

cfssl sign -ca /etc/cfssl/centminmod.com-ca.pem -ca-key /etc/cfssl/centminmod.com-ca-key.pem -config /etc/cfssl/profile.json -profile intermediate_ca centminmod.comca-intermediate.csr | cfssljson -bare centminmod.com-ca-intermediate
2020/09/13 07:45:26 [INFO] signed certificate with serial number 497566547131050114364562804974460766304515932901

openssl x509 -in centminmod.com-ca-intermediate.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            57:27:a7:d7:46:d9:3b:3b:63:ec:e2:54:f6:3c:bc:b3:20:1c:42:e5
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=Root CA
        Validity
            Not Before: Sep 13 07:40:00 2020 GMT
            Not After : Sep 11 07:40:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:58:f4:3d:fd:61:ba:3a:f5:7f:45:04:45:51:56:
                    ef:ac:cc:cc:9e:0c:3e:52:7e:67:1c:ce:61:4e:37:
                    bd:f5:e6:43:9a:94:3a:53:ae:15:88:78:a8:3d:35:
                    c2:c0:1e:17:86:4a:f6:a9:1c:92:5c:89:89:ff:bb:
                    45:cd:96:8d:e4
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Certificate Sign, CRL Sign
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8
            X509v3 Authority Key Identifier: 
                keyid:8C:26:8E:C6:7E:48:E7:98:3B:85:A9:CD:A4:6F:1D:B3:C4:7C:FC:25

    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:ef:d5:3a:32:27:0e:fe:d7:f7:a3:f1:d5:c2:
         e0:3f:aa:e0:dd:47:cf:e2:c5:bd:09:01:93:bb:37:01:6a:af:
         08:02:20:30:f3:70:89:39:9c:8b:e2:ce:25:5a:b1:5d:14:47:
         21:7f:48:c3:2b:5c:dd:91:c8:d5:0f:8b:63:6b:f4:9b:9f

ca intermediate cert: /etc/cfssl/centminmod.com-ca-intermediate.pem
ca intermediate key: /etc/cfssl/centminmod.com-ca-intermediate-key.pem
ca intermediate csr: /etc/cfssl/centminmod.com-ca-intermediate.csr
ca intermediate csr profile: /etc/cfssl/centminmod.com-ca-intermediate.csr.json
ca intermediate profile: /etc/cfssl/profile.json

{
  "subject": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "issuer": {
    "common_name": "Root CA",
    "country": "US",
    "organizational_unit": "Root CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Root CA",
      "Root CA"
    ]
  },
  "serial_number": "497566547131050114364562804974460766304515932901",
  "not_before": "2020-09-13T07:40:00Z",
  "not_after": "2030-09-11T07:40:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "8C:26:8E:C6:7E:48:E7:98:3B:85:A9:CD:A4:6F:1D:B3:C4:7C:FC:25",
  "subject_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIUVyen10bZOztj7OJU9jy8syAcQuUwCgYIKoZIzj0EAwIw\nVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRAwDgYDVQQLEwdSb290IENBMRAwDgYDVQQDEwdSb290IENBMB4XDTIwMDkx\nMzA3NDAwMFoXDTMwMDkxMTA3NDAwMFowZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgT\nAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlh\ndGUgQ0ExGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABFj0Pf1hujr1f0UERVFW76zMzJ4MPlJ+ZxzOYU43vfXmQ5qUOlOu\nFYh4qD01wsAeF4ZK9qkcklyJif+7Rc2WjeSjgYYwgYMwDgYDVR0PAQH/BAQDAgGm\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/\nAgEAMB0GA1UdDgQWBBRi9LjF1FiAqqvqZltSWrI9L/pLyDAfBgNVHSMEGDAWgBSM\nJo7GfkjnmDuFqc2kbx2zxHz8JTAKBggqhkjOPQQDAgNIADBFAiEA79U6MicO/tf3\no/HVwuA/quDdR8/ixb0JAZO7NwFqrwgCIDDzcIk5nIviziVasV0URyF/SMMrXN2R\nyNUPi2Nr9Juf\n-----END CERTIFICATE-----\n"
}

CA Bundle generated: /etc/cfssl/centminmod.com-ca-bundle.pem

cat /etc/cfssl/centminmod.com-ca.pem /etc/cfssl/centminmod.com-ca-intermediate.pem > /etc/cfssl/centminmod.com-ca-bundle.pem
```

# Server Wildcard SSL Certificate

Generate self-signed server wildcard SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication` using `wildcard` option.

* server cert: /etc/cfssl/servercerts/centminmod.com.pem
* server key: /etc/cfssl/servercerts/centminmod.com-key.pem
* server csr: /etc/cfssl/servercerts/centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 wildcard centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/13 07:46:31 [INFO] generate received request
2020/09/13 07:46:31 [INFO] received CSR
2020/09/13 07:46:31 [INFO] generating key: ecdsa-256
2020/09/13 07:46:31 [INFO] encoded CSR
2020/09/13 07:46:31 [INFO] signed certificate with serial number 167762260252919300310532144788403919043858146990

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1d:62:b8:4d:05:6e:2f:82:74:41:df:ab:f9:a4:5f:43:f4:fe:26:ae
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 07:42:00 2020 GMT
            Not After : Sep 11 07:42:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:a7:04:34:ae:6c:35:6c:87:5d:83:44:50:26:f2:
                    3d:05:20:28:ae:79:76:10:5d:bc:63:c8:34:e6:4a:
                    bb:f0:39:38:ee:ea:f2:30:dd:37:18:cb:28:fc:17:
                    a2:79:35:dd:f4:d7:d1:de:8e:f8:56:07:a7:2b:98:
                    7d:68:ab:5b:77
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                26:8F:47:88:04:2C:16:B0:7C:39:2F:3E:9A:3B:7F:10:4C:99:D2:B5
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:da:2f:2f:32:f6:ac:d1:f5:4d:8b:d5:df:0c:
         24:7a:80:be:57:63:ce:15:3c:a9:d6:cb:da:6d:62:d7:30:a5:
         86:02:21:00:9b:0e:1e:a4:45:83:24:56:a5:d8:3a:cd:3f:12:
         9e:62:b2:26:91:51:f3:02:96:6b:49:d4:0e:4c:01:8c:9b:9b

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server key: /etc/cfssl/servercerts/centminmod.com-key.pem
server csr: /etc/cfssl/servercerts/centminmod.com.csr
server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

Nginx SSL configuration paramaters:
ssl_certificate      /etc/cfssl/servercerts/centminmod.com.pem;
ssl_certificate_key  /etc/cfssl/servercerts/centminmod.com-key.pem;

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "167762260252919300310532144788403919043858146990",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-13T07:42:00Z",
  "not_after": "2030-09-11T07:42:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "26:8F:47:88:04:2C:16:B0:7C:39:2F:3E:9A:3B:7F:10:4C:99:D2:B5",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICWDCCAf2gAwIBAgIUHWK4TQVuL4J0Qd+r+aRfQ/T+Jq4wCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwNzQyMDBaFw0zMDA5MTEwNzQyMDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASn\nBDSubDVsh12DRFAm8j0FICiueXYQXbxjyDTmSrvwOTju6vIw3TcYyyj8F6J5Nd30\n19HejvhWB6crmH1oq1t3o4GjMIGgMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQmj0eIBCwWsHw5Lz6a\nO38QTJnStTAfBgNVHSMEGDAWgBRi9LjF1FiAqqvqZltSWrI9L/pLyDArBgNVHREE\nJDAigg5jZW50bWlubW9kLmNvbYIQKi5jZW50bWlubW9kLmNvbTAKBggqhkjOPQQD\nAgNJADBGAiEA2i8vMvas0fVNi9XfDCR6gL5XY84VPKnWy9ptYtcwpYYCIQCbDh6k\nRYMkVqXYOs0/Ep5isiaRUfMClmtJ1A5MAYybmw==\n-----END CERTIFICATE-----\n"
}
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

* server cert: /etc/cfssl/servercerts/centminmod.com.pem
* server key: /etc/cfssl/servercerts/centminmod.com-key.pem
* server csr: /etc/cfssl/servercerts/centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

domain with www subdomain inclusion tag `www centminmod.com` on end

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 www centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/13 07:48:20 [INFO] generate received request
2020/09/13 07:48:20 [INFO] received CSR
2020/09/13 07:48:20 [INFO] generating key: ecdsa-256
2020/09/13 07:48:20 [INFO] encoded CSR
2020/09/13 07:48:20 [INFO] signed certificate with serial number 81546263190456353690230886280096892110415495223

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0e:48:a9:31:47:12:40:16:32:b3:a9:69:62:74:49:06:37:fa:80:37
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 07:43:00 2020 GMT
            Not After : Sep 11 07:43:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:48:5f:2e:d3:bc:3f:e1:df:07:99:eb:9a:4f:ac:
                    ab:e2:e4:91:d4:a9:f6:e9:ca:65:2a:7f:e3:ef:75:
                    95:e8:cb:6d:50:30:ab:f1:5e:68:c4:cc:a0:b2:db:
                    2d:ea:72:f2:e8:3e:73:6d:6c:e5:66:40:34:43:56:
                    0b:87:ee:71:e8
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                73:DD:CA:14:C5:9E:3F:24:CE:B0:C6:6A:E6:11:44:CB:7B:9D:46:89
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:www.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:57:e6:3c:1b:39:22:a0:41:b7:51:69:cd:3a:7f:
         d7:8c:82:f2:86:9b:e2:0a:a8:79:ac:a8:b2:8b:60:bf:58:69:
         02:21:00:8d:50:d3:a8:02:d4:ff:2b:03:f3:20:d5:4f:2a:19:
         b9:1b:ec:03:48:e2:cf:e7:8c:84:1b:12:99:06:1a:17:87

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server key: /etc/cfssl/servercerts/centminmod.com-key.pem
server csr: /etc/cfssl/servercerts/centminmod.com.csr
server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

Nginx SSL configuration paramaters:
ssl_certificate      /etc/cfssl/servercerts/centminmod.com.pem;
ssl_certificate_key  /etc/cfssl/servercerts/centminmod.com-key.pem;

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "81546263190456353690230886280096892110415495223",
  "sans": [
    "centminmod.com",
    "www.centminmod.com"
  ],
  "not_before": "2020-09-13T07:43:00Z",
  "not_after": "2030-09-11T07:43:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "73:DD:CA:14:C5:9E:3F:24:CE:B0:C6:6A:E6:11:44:CB:7B:9D:46:89",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICWTCCAf+gAwIBAgIUDkipMUcSQBYys6lpYnRJBjf6gDcwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwNzQzMDBaFw0zMDA5MTEwNzQzMDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARI\nXy7TvD/h3weZ65pPrKvi5JHUqfbpymUqf+PvdZXoy21QMKvxXmjEzKCy2y3qcvLo\nPnNtbOVmQDRDVguH7nHoo4GlMIGiMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRz3coUxZ4/JM6wxmrm\nEUTLe51GiTAfBgNVHSMEGDAWgBRi9LjF1FiAqqvqZltSWrI9L/pLyDAtBgNVHREE\nJjAkgg5jZW50bWlubW9kLmNvbYISd3d3LmNlbnRtaW5tb2QuY29tMAoGCCqGSM49\nBAMCA0gAMEUCIFfmPBs5IqBBt1FpzTp/14yC8oab4gqoeayosotgv1hpAiEAjVDT\nqALU/ysD8yDVTyoZuRvsA0jiz+eMhBsSmQYaF4c=\n-----END CERTIFICATE-----\n"
}
```

domain without `www` inclusion

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/13 07:49:00 [INFO] generate received request
2020/09/13 07:49:00 [INFO] received CSR
2020/09/13 07:49:00 [INFO] generating key: ecdsa-256
2020/09/13 07:49:00 [INFO] encoded CSR
2020/09/13 07:49:00 [INFO] signed certificate with serial number 255697584086276948700266816507316830566460739535

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            2c:c9:e0:50:07:e3:64:88:7d:91:90:3b:fe:10:03:4b:82:ec:cf:cf
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 07:44:00 2020 GMT
            Not After : Sep 11 07:44:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:7c:67:e6:44:59:92:12:7a:03:8a:41:8e:3d:e7:
                    d2:81:a1:be:f5:e4:e6:49:ce:21:97:5b:aa:4e:56:
                    e8:dd:73:0c:8d:a8:ee:fe:79:cb:27:52:04:37:d2:
                    14:3d:ea:d3:b8:a4:72:97:06:4c:a8:6e:99:81:38:
                    c5:98:75:77:e2
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                68:0B:A1:78:1C:01:27:88:C0:E8:48:1B:76:26:8F:03:71:59:C5:B4
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:6b:66:eb:1f:31:eb:71:e9:25:b5:f2:3a:62:b2:
         f6:77:72:c8:3b:93:8d:2a:ca:ca:9d:35:f4:8c:71:fe:4e:1c:
         02:20:3b:fe:43:2e:e5:7f:71:b1:b4:6a:41:0c:2f:c3:1b:e0:
         27:55:61:8f:ae:0e:8a:2b:6b:de:0c:2e:36:86:a8:58

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server key: /etc/cfssl/servercerts/centminmod.com-key.pem
server csr: /etc/cfssl/servercerts/centminmod.com.csr
server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

Nginx SSL configuration paramaters:
ssl_certificate      /etc/cfssl/servercerts/centminmod.com.pem;
ssl_certificate_key  /etc/cfssl/servercerts/centminmod.com-key.pem;

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "255697584086276948700266816507316830566460739535",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-13T07:44:00Z",
  "not_after": "2030-09-11T07:44:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "68:0B:A1:78:1C:01:27:88:C0:E8:48:1B:76:26:8F:03:71:59:C5:B4",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRDCCAeugAwIBAgIULMngUAfjZIh9kZA7/hADS4Lsz88wCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwNzQ0MDBaFw0zMDA5MTEwNzQ0MDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR8\nZ+ZEWZISegOKQY4959KBob715OZJziGXW6pOVujdcwyNqO7+ecsnUgQ30hQ96tO4\npHKXBkyobpmBOMWYdXfio4GRMIGOMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRoC6F4HAEniMDoSBt2\nJo8DcVnFtDAfBgNVHSMEGDAWgBRi9LjF1FiAqqvqZltSWrI9L/pLyDAZBgNVHREE\nEjAQgg5jZW50bWlubW9kLmNvbTAKBggqhkjOPQQDAgNHADBEAiBrZusfMetx6SW1\n8jpisvZ3csg7k40qysqdNfSMcf5OHAIgO/5DLuV/cbG0akEML8Mb4CdVYY+uDoor\na94MLjaGqFg=\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

* server cert: /etc/cfssl/servercerts/server.centminmod.com.pem
* server key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
* server csr: /etc/cfssl/servercerts/server.centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/server.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn server.centminmod.com -hostname server.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem server.centminmod.com.csr.json > server.centminmod.com.json
2020/09/13 07:49:29 [INFO] generate received request
2020/09/13 07:49:29 [INFO] received CSR
2020/09/13 07:49:29 [INFO] generating key: ecdsa-256
2020/09/13 07:49:29 [INFO] encoded CSR
2020/09/13 07:49:29 [INFO] signed certificate with serial number 118739610410025159352075757120563634816142566312

cfssljson -f server.centminmod.com.json -bare server.centminmod.com


openssl x509 -in server.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            14:cc:77:e1:23:ba:2e:3f:32:98:ad:50:5e:d6:bb:a7:b8:38:63:a8
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 07:44:00 2020 GMT
            Not After : Sep 11 07:44:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:f2:da:32:fd:7d:79:7c:68:84:33:7d:16:83:e4:
                    3e:bf:f6:e3:87:28:86:86:04:cf:6f:98:b8:c0:45:
                    ef:40:61:01:08:e2:3c:f1:7b:a6:2b:0c:f7:71:16:
                    88:83:bc:c3:3d:87:16:c9:79:a4:e5:f4:29:66:77:
                    d5:5c:da:b7:ae
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                54:25:D6:D6:21:6C:FB:FD:A0:A1:DC:B4:C8:80:3D:54:95:48:41:89
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:36:37:d7:25:b5:b8:34:ca:13:34:a5:f8:e2:c9:
         7c:f2:c3:19:e2:c3:f6:cd:40:e4:a7:92:97:8a:65:ab:86:a6:
         02:21:00:f0:f9:16:ef:b2:4e:80:fa:09:e2:02:a9:d5:8d:c8:
         ff:f2:e5:d1:96:fa:ba:60:79:aa:cb:10:d4:d2:12:7f:dc

server cert: /etc/cfssl/servercerts/server.centminmod.com.pem
server key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
server csr: /etc/cfssl/servercerts/server.centminmod.com.csr
server csr profile: /etc/cfssl/servercerts/server.centminmod.com.csr.json

Nginx SSL configuration paramaters:
ssl_certificate      /etc/cfssl/servercerts/server.centminmod.com.pem;
ssl_certificate_key  /etc/cfssl/servercerts/server.centminmod.com-key.pem;

{
  "subject": {
    "common_name": "server.centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "server.centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "118739610410025159352075757120563634816142566312",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-13T07:44:00Z",
  "not_after": "2030-09-11T07:44:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "54:25:D6:D6:21:6C:FB:FD:A0:A1:DC:B4:C8:80:3D:54:95:48:41:89",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICUzCCAfmgAwIBAgIUFMx34SO6Lj8ymK1QXta7p7g4Y6gwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwNzQ0MDBaFw0zMDA5MTEwNzQ0MDBaMFIxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEeMBwG\nA1UEAxMVc2VydmVyLmNlbnRtaW5tb2QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAE8toy/X15fGiEM30Wg+Q+v/bjhyiGhgTPb5i4wEXvQGEBCOI88XumKwz3\ncRaIg7zDPYcWyXmk5fQpZnfVXNq3rqOBmDCBlTAOBgNVHQ8BAf8EBAMCBaAwEwYD\nVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUVCXW1iFs\n+/2gody0yIA9VJVIQYkwHwYDVR0jBBgwFoAUYvS4xdRYgKqr6mZbUlqyPS/6S8gw\nIAYDVR0RBBkwF4IVc2VydmVyLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0gA\nMEUCIDY31yW1uDTKEzSl+OLJfPLDGeLD9s1A5KeSl4plq4amAiEA8PkW77JOgPoJ\n4gKp1Y3I//Ll0Zb6umB5qssQ1NISf9w=\n-----END CERTIFICATE-----\n"
}
```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

* client pkcs12: /etc/cfssl/clientcerts/centminmod.com.p12
* client cert: /etc/cfssl/clientcerts/centminmod.com.pem
* client key: /etc/cfssl/clientcerts/centminmod.com-key.pem
* client csr: /etc/cfssl/clientcerts/centminmod.com.csr
* client csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/13 08:20:28 [INFO] generate received request
2020/09/13 08:20:28 [INFO] received CSR
2020/09/13 08:20:28 [INFO] generating key: ecdsa-256
2020/09/13 08:20:28 [INFO] encoded CSR
2020/09/13 08:20:28 [INFO] signed certificate with serial number 668333411754618667395411706882887132789280754657

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            75:11:1b:4e:f5:56:6e:dd:71:e5:aa:91:71:10:64:cd:34:76:4b:e1
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 08:15:00 2020 GMT
            Not After : Sep 11 08:15:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:f7:86:82:29:ca:1a:af:15:41:04:e5:c2:e4:3a:
                    0b:1d:9a:90:01:68:d9:48:a1:27:93:d5:8d:b7:e7:
                    56:39:99:a6:f7:17:1f:ce:e6:88:77:87:9b:f0:2a:
                    72:64:1b:4d:95:0a:e2:7e:53:7c:8b:9a:dc:98:c2:
                    76:88:9e:e7:66
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                5B:A5:D3:B4:3C:F7:53:16:45:49:06:27:B3:F5:A7:37:7E:75:6A:9A
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:57:f0:76:8a:95:ba:c6:34:30:78:af:fa:8a:41:
         46:c2:c2:61:da:83:bb:9c:db:eb:f4:2e:16:93:8f:e0:55:d3:
         02:21:00:b7:cd:1a:31:56:97:7f:f2:67:a6:50:89:45:3f:1f:
         c4:5b:91:be:cf:e6:2f:e6:97:5c:bc:c3:73:29:1a:fd:d8

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/clientcerts/centminmod.com.p12 -inkey /etc/cfssl/clientcerts/centminmod.com-key.pem -in /etc/cfssl/clientcerts/centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

client pkcs12: /etc/cfssl/clientcerts/centminmod.com.p12
client cert: /etc/cfssl/clientcerts/centminmod.com.pem
client key: /etc/cfssl/clientcerts/centminmod.com-key.pem
client csr: /etc/cfssl/clientcerts/centminmod.com.csr
client csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "668333411754618667395411706882887132789280754657",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-13T08:15:00Z",
  "not_after": "2030-09-11T08:15:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "5B:A5:D3:B4:3C:F7:53:16:45:49:06:27:B3:F5:A7:37:7E:75:6A:9A",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIUdREbTvVWbt1x5aqRcRBkzTR2S+EwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwODE1MDBaFw0zMDA5MTEwODE1MDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT3\nhoIpyhqvFUEE5cLkOgsdmpABaNlIoSeT1Y2351Y5mab3Fx/O5oh3h5vwKnJkG02V\nCuJ+U3yLmtyYwnaInudmo4GRMIGOMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRbpdO0PPdTFkVJBiez\n9ac3fnVqmjAfBgNVHSMEGDAWgBRi9LjF1FiAqqvqZltSWrI9L/pLyDAZBgNVHREE\nEjAQgg5jZW50bWlubW9kLmNvbTAKBggqhkjOPQQDAgNIADBFAiBX8HaKlbrGNDB4\nr/qKQUbCwmHag7uc2+v0LhaTj+BV0wIhALfNGjFWl3/yZ6ZQiUU/H8Rbkb7P5i/m\nl1y8w3MpGv3Y\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

* client pkcs12: /etc/cfssl/clientcerts/client.centminmod.com.p12
* client cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
* client key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
* client csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
* client csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn client.centminmod.com -hostname client.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem client.centminmod.com.csr.json > client.centminmod.com.json
2020/09/13 08:21:04 [INFO] generate received request
2020/09/13 08:21:04 [INFO] received CSR
2020/09/13 08:21:04 [INFO] generating key: ecdsa-256
2020/09/13 08:21:04 [INFO] encoded CSR
2020/09/13 08:21:04 [INFO] signed certificate with serial number 642527497706939225812196864086885765612876070103

cfssljson -f client.centminmod.com.json -bare client.centminmod.com


openssl x509 -in client.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            70:8b:ed:f1:81:97:87:0b:fc:50:2d:e0:70:c7:9f:9a:c1:53:fc:d7
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 08:16:00 2020 GMT
            Not After : Sep 11 08:16:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:99:5d:bc:a6:72:a1:ac:61:56:32:6b:f9:c5:d7:
                    f4:ff:fb:2f:b1:ab:81:fc:1c:7f:b6:24:ac:2c:78:
                    4f:3a:be:ca:58:58:98:67:7b:51:55:4d:18:0a:d7:
                    2f:c3:0d:03:02:34:a0:d6:09:5a:28:16:21:3a:e1:
                    13:60:3a:21:6e
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                67:46:DC:61:12:07:6E:80:1E:51:04:7B:09:B7:18:F4:CC:2F:2E:EE
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:62:2b:c8:fc:c2:32:44:a4:35:d0:16:13:b9:83:
         4f:c8:e4:cc:a0:07:af:28:9a:47:d4:a1:8f:90:d4:89:8a:0f:
         02:21:00:f6:18:39:6d:85:02:e3:88:04:d6:11:4b:8d:51:f8:
         1f:20:80:c4:97:20:6f:2d:0c:8e:93:b2:79:a8:b0:c6:c6

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/clientcerts/client.centminmod.com.p12 -inkey /etc/cfssl/clientcerts/client.centminmod.com-key.pem -in /etc/cfssl/clientcerts/client.centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

client pkcs12: /etc/cfssl/clientcerts/client.centminmod.com.p12
client cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
client key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
client csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
client csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json

{
  "subject": {
    "common_name": "client.centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "client.centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "642527497706939225812196864086885765612876070103",
  "sans": [
    "client.centminmod.com"
  ],
  "not_before": "2020-09-13T08:16:00Z",
  "not_after": "2030-09-11T08:16:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "67:46:DC:61:12:07:6E:80:1E:51:04:7B:09:B7:18:F4:CC:2F:2E:EE",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICUzCCAfmgAwIBAgIUcIvt8YGXhwv8UC3gcMefmsFT/NcwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwODE2MDBaFw0zMDA5MTEwODE2MDBaMFIxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEeMBwG\nA1UEAxMVY2xpZW50LmNlbnRtaW5tb2QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAEmV28pnKhrGFWMmv5xdf0//svsauB/Bx/tiSsLHhPOr7KWFiYZ3tRVU0Y\nCtcvww0DAjSg1glaKBYhOuETYDohbqOBmDCBlTAOBgNVHQ8BAf8EBAMCBaAwEwYD\nVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUZ0bcYRIH\nboAeUQR7CbcY9MwvLu4wHwYDVR0jBBgwFoAUYvS4xdRYgKqr6mZbUlqyPS/6S8gw\nIAYDVR0RBBkwF4IVY2xpZW50LmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0gA\nMEUCIGIryPzCMkSkNdAWE7mDT8jkzKAHryiaR9Shj5DUiYoPAiEA9hg5bYUC44gE\n1hFLjVH4HyCAxJcgby0MjpOyeaiwxsY=\n-----END CERTIFICATE-----\n"
}
```

# Peer Wildcard SSL Certificate

Generate self-signed peer wildcard SSL certificate with CA signing for centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

* peer pkcs12: /etc/cfssl/peercerts/centminmod.com.p12
* peer cert: /etc/cfssl/peercerts/centminmod.com.pem
* peer key: /etc/cfssl/peercerts/centminmod.com-key.pem
* peer csr: /etc/cfssl/peercerts/centminmod.com.csr
* peer csr profile: /etc/cfssl/peercerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 wildcard centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile peer -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/13 08:21:31 [INFO] generate received request
2020/09/13 08:21:31 [INFO] received CSR
2020/09/13 08:21:31 [INFO] generating key: ecdsa-256
2020/09/13 08:21:31 [INFO] encoded CSR
2020/09/13 08:21:31 [INFO] signed certificate with serial number 489648551547225836955778835577261673832650599244

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            55:c4:99:b5:94:87:ec:a6:00:08:c3:87:d7:61:2d:1c:10:6b:6b:4c
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 08:17:00 2020 GMT
            Not After : Sep 11 08:17:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:f0:a4:f0:4a:17:5d:a4:ed:28:89:9d:02:27:9b:
                    ab:2b:6c:46:9c:db:ea:4d:76:3c:d6:86:af:33:ff:
                    73:97:dc:a1:53:4f:57:12:37:9c:f3:f8:73:b8:32:
                    01:55:ce:61:ee:c3:d3:91:3b:30:31:11:6b:7f:09:
                    92:70:0b:0a:4d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                0A:8C:5C:C1:DA:B2:D9:59:DA:F8:C0:47:9F:44:33:2F:F6:B5:06:15
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:9b:a6:05:1f:f7:26:2e:09:98:c2:b7:29:24:
         42:b0:67:17:0f:0e:15:80:c0:0b:28:5d:d7:c2:ec:c9:64:58:
         fe:02:21:00:c1:ff:7e:94:99:7a:1a:6c:3a:64:6f:b1:6c:52:
         c7:f9:bd:b5:14:0e:ab:a9:f0:9d:7f:8a:45:9b:c5:b0:43:e4

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/peercerts/centminmod.com.p12 -inkey /etc/cfssl/peercerts/centminmod.com-key.pem -in /etc/cfssl/peercerts/centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

peer pkcs12: /etc/cfssl/peercerts/centminmod.com.p12
peer cert: /etc/cfssl/peercerts/centminmod.com.pem
peer key: /etc/cfssl/peercerts/centminmod.com-key.pem
peer csr: /etc/cfssl/peercerts/centminmod.com.csr
peer csr profile: /etc/cfssl/peercerts/centminmod.com.csr.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "489648551547225836955778835577261673832650599244",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-13T08:17:00Z",
  "not_after": "2030-09-11T08:17:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "0A:8C:5C:C1:DA:B2:D9:59:DA:F8:C0:47:9F:44:33:2F:F6:B5:06:15",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICYjCCAgegAwIBAgIUVcSZtZSH7KYACMOH12EtHBBra0wwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwODE3MDBaFw0zMDA5MTEwODE3MDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATw\npPBKF12k7SiJnQInm6srbEac2+pNdjzWhq8z/3OX3KFTT1cSN5zz+HO4MgFVzmHu\nw9OROzAxEWt/CZJwCwpNo4GtMIGqMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAU\nBggrBgEFBQcDAgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUCoxc\nwdqy2Vna+MBHn0QzL/a1BhUwHwYDVR0jBBgwFoAUYvS4xdRYgKqr6mZbUlqyPS/6\nS8gwKwYDVR0RBCQwIoIOY2VudG1pbm1vZC5jb22CECouY2VudG1pbm1vZC5jb20w\nCgYIKoZIzj0EAwIDSQAwRgIhAJumBR/3Ji4JmMK3KSRCsGcXDw4VgMALKF3XwuzJ\nZFj+AiEAwf9+lJl6Gmw6ZG+xbFLH+b21FA6rqfCdf4pFm8WwQ+Q=\n-----END CERTIFICATE-----\n"
}
```

# Peer SSL Certificate

Generate self-signed peer SSL certificate with CA signing for peer.centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

* peer pkcs12: /etc/cfssl/peercerts/peer.centminmod.com.p12
* peer cert: /etc/cfssl/peercerts/peer.centminmod.com.pem
* peer key: /etc/cfssl/peercerts/peer.centminmod.com-key.pem
* peer csr: /etc/cfssl/peercerts/peer.centminmod.com.csr
* peer csr profile: /etc/cfssl/peercerts/peer.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 peer centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile peer -cn peer.centminmod.com -hostname peer.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem peer.centminmod.com.csr.json > peer.centminmod.com.json
2020/09/13 08:22:07 [INFO] generate received request
2020/09/13 08:22:07 [INFO] received CSR
2020/09/13 08:22:07 [INFO] generating key: ecdsa-256
2020/09/13 08:22:07 [INFO] encoded CSR
2020/09/13 08:22:07 [INFO] signed certificate with serial number 138479072846140899647021478866647107307146180596

cfssljson -f peer.centminmod.com.json -bare peer.centminmod.com


openssl x509 -in peer.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            18:41:9d:cb:98:28:69:9c:12:8f:8a:4b:fd:c3:87:40:12:09:f7:f4
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 13 08:17:00 2020 GMT
            Not After : Sep 11 08:17:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=peer.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:69:15:05:74:ea:8c:5e:fe:4c:3c:74:1d:80:c4:
                    ac:7d:4a:34:2c:aa:c8:07:12:a5:3e:d6:f5:b7:59:
                    5c:c9:fc:8f:a8:ff:11:d6:18:41:c4:1a:5d:ea:c3:
                    0b:34:c3:94:21:23:a0:1d:0c:fe:ba:8f:d8:c0:69:
                    50:92:7e:bc:cd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                B9:B3:51:F9:0B:BD:42:27:8F:E6:99:BA:12:9F:10:BF:D6:CB:3A:4C
            X509v3 Authority Key Identifier: 
                keyid:62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8

            X509v3 Subject Alternative Name: 
                DNS:peer.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:50:e9:5c:4c:18:d0:65:af:34:34:8c:fa:ba:0e:
         b5:84:1e:fc:08:d3:ac:2d:19:f6:df:5b:16:b5:49:67:20:a6:
         02:20:1f:d1:a9:9e:e2:56:50:fa:09:17:46:1b:37:e5:57:09:
         2e:f6:61:45:51:1b:46:50:76:eb:89:c0:dd:b5:c8:47

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/peercerts/peer.centminmod.com.p12 -inkey /etc/cfssl/peercerts/peer.centminmod.com-key.pem -in /etc/cfssl/peercerts/peer.centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

peer pkcs12: /etc/cfssl/peercerts/peer.centminmod.com.p12
peer cert: /etc/cfssl/peercerts/peer.centminmod.com.pem
peer key: /etc/cfssl/peercerts/peer.centminmod.com-key.pem
peer csr: /etc/cfssl/peercerts/peer.centminmod.com.csr
peer csr profile: /etc/cfssl/peercerts/peer.centminmod.com.csr.json

{
  "subject": {
    "common_name": "peer.centminmod.com",
    "country": "US",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "peer.centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "Intermediate CA",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "Intermediate CA"
    ]
  },
  "serial_number": "138479072846140899647021478866647107307146180596",
  "sans": [
    "peer.centminmod.com"
  ],
  "not_before": "2020-09-13T08:17:00Z",
  "not_after": "2030-09-11T08:17:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "62:F4:B8:C5:D4:58:80:AA:AB:EA:66:5B:52:5A:B2:3D:2F:FA:4B:C8",
  "subject_key_id": "B9:B3:51:F9:0B:BD:42:27:8F:E6:99:BA:12:9F:10:BF:D6:CB:3A:4C",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICWDCCAf+gAwIBAgIUGEGdy5goaZwSj4pL/cOHQBIJ9/QwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTMwODE3MDBaFw0zMDA5MTEwODE3MDBaMFAxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEcMBoG\nA1UEAxMTcGVlci5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABGkVBXTqjF7+TDx0HYDErH1KNCyqyAcSpT7W9bdZXMn8j6j/EdYYQcQaXerD\nCzTDlCEjoB0M/rqP2MBpUJJ+vM2jgaAwgZ0wDgYDVR0PAQH/BAQDAgWgMB0GA1Ud\nJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW\nBBS5s1H5C71CJ4/mmboSnxC/1ss6TDAfBgNVHSMEGDAWgBRi9LjF1FiAqqvqZltS\nWrI9L/pLyDAeBgNVHREEFzAVghNwZWVyLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49\nBAMCA0cAMEQCIFDpXEwY0GWvNDSM+roOtYQe/AjTrC0Z9t9bFrVJZyCmAiAf0ame\n4lZQ+gkXRhs35VcJLvZhRVEbRlB264nA3bXIRw==\n-----END CERTIFICATE-----\n"
}
```

# Nginx Configuration

```
cp -a /etc/cfssl/centminmod.com-ca-bundle.pem /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem
```

```
ssl_client_certificate /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem;
ssl_verify_client on;
ssl_verify_depth 1;

if ($ssl_client_verify != SUCCESS) {
    return 403;
}
```

# Browser Client TLS Authentication

Opera Web Browser Client connection for domain https://cems.msdomain.com adding generated client pkcs12 file `/etc/cfssl/clientcerts/cems.msdomain.com.p12` to Opera browser certificates management store.

```
# create CA & CA Intermediate certs
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca centminmod.com 87600

# create client TLS certificate for cems.msdomain.com
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 cems msdomain.com
```

client TLS certificates generated for cems.msdomain.com

* client pkcs12: /etc/cfssl/clientcerts/cems.msdomain.com.p12
* client cert: /etc/cfssl/clientcerts/cems.msdomain.com.pem
* client key: /etc/cfssl/clientcerts/cems.msdomain.com-key.pem
* client csr: /etc/cfssl/clientcerts/cems.msdomain.com.csr
* client csr profile: /etc/cfssl/clientcerts/cems.msdomain.com.csr.json
* client bundle chain: /etc/cfssl/clientcerts/cems.msdomain.com-client-bundle.pem

Opera Browser

Using Opera browser to access site without client TLS certificate will give 400 Bad Request error and prevent site access

![opera](/screenshots/nginx-tls-client-authentictaion-01.png)

Add to Opera Manage Certificates store the generated client pkcs12 file `/etc/cfssl/clientcerts/cems.msdomain.com.p12`

![opera](/screenshots/opera-manage-certificates-01.png)
![opera](/screenshots/opera-manage-certificates-02.png)
![opera](/screenshots/opera-manage-certificates-03.png)
![opera](/screenshots/opera-manage-certificates-04.png)
![opera](/screenshots/opera-manage-certificates-05.png)
![opera](/screenshots/opera-manage-certificates-06.png)
![opera](/screenshots/opera-manage-certificates-07.png)
![opera](/screenshots/opera-manage-certificates-08.png)

Intended purpose = Client Authentication

![opera](/screenshots/opera-manage-certificates-09.png)

Opera browser first time only prompt to select the imported client TLS certificate to use to authenticate against https://cems.msdomain.com Nginx site.

![opera](/screenshots/opera-manage-certificates-10.png)

Once authenticated, subsequent access via Opera browser is permitted

![opera](/screenshots/opera-manage-certificates-11.png)

# Curl Client TLS Authentication

For CentOS 7.x curl, need to add the generated client pkcs12 file `/etc/cfssl/clientcerts/cems.msdomain.com.p12` to nssdb database used by curl. Otherwise, curl requests will get a `HTTP/1.1 400 Bad Request` response. At password prompt just hit enter as no password was assigned.

```
pk12util -d sql:/etc/pki/nssdb -i /etc/cfssl/clientcerts/cems.msdomain.com.p12
Enter password for PKCS12 file: 
pk12util: no nickname for cert in PKCS12 file.
pk12util: using nickname: cems.msdomain.com
pk12util: PKCS12 IMPORT SUCCESSFUL
```

Check added certificate via certutil command

```
certutil -d sql:/etc/pki/nssdb -L -n cems.msdomain.com
```

output

```
certutil -d sql:/etc/pki/nssdb -L -n cems.msdomain.com
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            69:bd:8b:8d:11:2b:05:19:c8:33:be:98:a4:8b:11:38:
            55:44:1c:11
        Signature Algorithm: X9.62 ECDSA signature with SHA256
        Issuer: "CN=Intermediate CA,OU=Intermediate CA,L=San Francisco,ST=CA,
            C=US"
        Validity:
            Not Before: Sun Sep 13 11:37:00 2020
            Not After : Wed Sep 11 11:37:00 2030
        Subject: "CN=cems.msdomain.com,L=San Francisco,ST=CA,C=US"
        Subject Public Key Info:
            Public Key Algorithm: X9.62 elliptic curve public key
                Args:
                    06:08:2a:86:48:ce:3d:03:01:07
            EC Public Key:
                PublicValue:
                    04:e2:aa:35:e6:fd:89:e5:ab:f5:b3:ac:97:5d:3d:fb:
                    cd:78:0f:9b:40:43:c1:7a:ce:e6:e4:d9:f9:0c:55:7c:
                    a1:3d:54:73:a1:e4:b3:22:b7:3a:ac:2b:fc:a5:ce:66:
                    ce:02:e0:7a:56:97:f7:15:e0:42:0f:bf:83:8b:d9:8a:
                    33
                Curve: ANSI X9.62 elliptic curve prime256v1 (aka secp256r1, NIST P-256)
        Signed Extensions:
            Name: Certificate Key Usage
            Critical: True
            Usages: Digital Signature
                    Key Encipherment

            Name: Extended Key Usage
                TLS Web Client Authentication Certificate

            Name: Certificate Basic Constraints
            Critical: True
            Data: Is not a CA.

            Name: Certificate Subject Key ID
            Data:
                53:7f:f5:cd:28:e9:db:e4:77:4e:73:2f:43:9a:57:22:
                9a:11:be:3d

            Name: Certificate Authority Key Identifier
            Key ID:
                aa:ec:ed:0a:75:07:ff:2a:e2:72:7e:e4:9a:58:35:70:
                6f:2f:7a:21

            Name: Certificate Subject Alt Name
            DNS name: "cems.msdomain.com"

    Signature Algorithm: X9.62 ECDSA signature with SHA256
    Signature:
        30:45:02:20:69:e1:17:a6:76:ca:19:a1:56:81:47:50:
        cd:ce:77:75:d1:a9:c6:fe:cd:c0:12:3b:73:a1:f6:e5:
        43:f2:c2:eb:02:21:00:f9:d1:5e:72:1f:cf:72:1b:54:
        3f:3b:91:4f:bb:24:6e:04:1e:61:e7:22:ca:fc:98:b0:
        f2:1c:08:94:d6:62:ed
    Fingerprint (SHA-256):
        3B:3C:C3:5A:86:A0:59:A2:DD:BC:88:C5:6A:DF:11:60:37:C3:9F:AE:28:22:2B:89:DE:83:2C:0E:6C:69:D8:13
    Fingerprint (SHA1):
        EC:B6:4E:64:17:A2:5E:7E:71:66:B6:3F:36:91:DA:90:96:00:C6:DB

    Mozilla-CA-Policy: false (attribute missing)
    Certificate Trust Flags:
        SSL Flags:
            User
        Email Flags:
            User
        Object Signing Flags:
            User
```

To remove it from nssdb database:

```
certutil -d sql:/etc/pki/nssdb -D -n cems.msdomain.com
```

verify you can connect via curl

```
curl -Ikv https://cems.msdomain.com
```

output - notice the line `NSS: using client certificate: cems.msdomain.com`

```
curl -Ikv https://cems.msdomain.com                                                 
* About to connect() to cems.msdomain.com port 443 (#0)
*   Trying 192.168.0.18...
* Connected to cems.msdomain.com (192.168.0.18) port 443 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
* skipping SSL peer certificate verification
* NSS: using client certificate: cems.msdomain.com
*       subject: CN=cems.msdomain.com,L=San Francisco,ST=CA,C=US
*       start date: Sep 13 11:37:00 2020 GMT
*       expire date: Sep 11 11:37:00 2030 GMT
*       common name: cems.msdomain.com
*       issuer: CN=Intermediate CA,OU=Intermediate CA,L=San Francisco,ST=CA,C=US
* SSL connection using TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* Server certificate:
*       subject: CN=cems.msdomain.com,L=San Francisco,ST=CA,C=US
*       start date: Sep 13 11:27:00 2020 GMT
*       expire date: Sep 11 11:27:00 2030 GMT
*       common name: cems.msdomain.com
*       issuer: CN=Intermediate CA,OU=Intermediate CA,L=San Francisco,ST=CA,C=US
> HEAD / HTTP/1.1
> User-Agent: curl/7.29.0
> Host: cems.msdomain.com
> Accept: */*
> 
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Date: Sun, 13 Sep 2020 13:25:53 GMT
Date: Sun, 13 Sep 2020 13:25:53 GMT
< Content-Type: text/html; charset=utf-8
Content-Type: text/html; charset=utf-8
< Content-Length: 6597
Content-Length: 6597
< Last-Modified: Sun, 13 Sep 2020 08:56:10 GMT
Last-Modified: Sun, 13 Sep 2020 08:56:10 GMT
< Connection: keep-alive
Connection: keep-alive
< Vary: Accept-Encoding
Vary: Accept-Encoding
< ETag: "5f5ddeaa-19c5"
ETag: "5f5ddeaa-19c5"
< Server: nginx centminmod
Server: nginx centminmod
< X-Powered-By: centminmod
X-Powered-By: centminmod
< X-Xss-Protection: 1; mode=block
X-Xss-Protection: 1; mode=block
< X-Content-Type-Options: nosniff
X-Content-Type-Options: nosniff
< Accept-Ranges: bytes
Accept-Ranges: bytes

< 
* Connection #0 to host cems.msdomain.com left intact
```

# Other Checks

```
echo -n | openssl s_client -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem -cert /etc/cfssl/clientcerts/cems.msdomain.com.pem -key /etc/cfssl/clientcerts/cems.msdomain.com-key.pem -connect cems.msdomain.com:443
```
```
echo -n | openssl s_client -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem -cert /etc/cfssl/clientcerts/cems.msdomain.com.pem -key /etc/cfssl/clientcerts/cems.msdomain.com-key.pem -connect cems.msdomain.com:443
.com:443
CONNECTED(00000003)
depth=2 C = US, ST = CA, L = San Francisco, OU = Root CA, CN = Root CA
verify return:1
depth=1 C = US, ST = CA, L = San Francisco, OU = Intermediate CA, CN = Intermediate CA
verify return:1
depth=0 C = US, ST = CA, L = San Francisco, CN = cems.msdomain.com
verify return:1
---
Certificate chain
 0 s:/C=US/ST=CA/L=San Francisco/CN=cems.msdomain.com
   i:/C=US/ST=CA/L=San Francisco/OU=Intermediate CA/CN=Intermediate CA
---
Server certificate
-----BEGIN CERTIFICATE-----
...snipped...
-----END CERTIFICATE-----
subject=/C=US/ST=CA/L=San Francisco/CN=cems.msdomain.com
issuer=/C=US/ST=CA/L=San Francisco/OU=Intermediate CA/CN=Intermediate CA
---
Acceptable client certificate CA names
/C=US/ST=CA/L=San Francisco/OU=Root CA/CN=Root CA
/C=US/ST=CA/L=San Francisco/OU=Intermediate CA/CN=Intermediate CA
Client Certificate Types: RSA sign, DSA sign, ECDSA sign
Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:0x07+0x08:0x08+0x08:0x09+0x08:0x0A+0x08:0x0B+0x08:0x04+0x08:0x05+0x08:0x06+0x08:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:ECDSA+SHA1:RSA+SHA224:RSA+SHA1:DSA+SHA224:DSA+SHA1:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:ECDSA+SHA1:RSA+SHA224:RSA+SHA1:DSA+SHA224:DSA+SHA1:DSA+SHA256:DSA+SHA384:DSA+SHA512
Peer signing digest: SHA256
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 1928 bytes and written 2193 bytes
---
New, TLSv1/SSLv3, Cipher is ECDHE-ECDSA-AES128-GCM-SHA256

...snipped...

    Start Time: 1600000287
    Timeout   : 300 (sec)
    Verify return code: 0 (ok)
---
DONE
```