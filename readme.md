Using [cfssl](https://github.com/cloudflare/cfssl) to generate a CA certificate/key and to sign server, client and peer self-signed SSL certificates with it. Mainly intended for [Centmin Mod LEMP stack](https://centminmod.com) installations on CentOS 7.x for creating Nginx based TLS/SSL client certificate authentication via [ssl_client_certificate](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate) and [ssl_verify_client](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) directives using [gen-client option](#client-ssl-certificate).

Nginx Configuration

```
cp -a /etc/cfssl/centminmod.com-ca-bundle.pem /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem
```

```
ssl_client_certificate /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem;
ssl_verify_client on;

if ($ssl_client_verify != SUCCESS) {
    return 403;
}
```

Client connection

```
curl -k --cert /etc/cfssl/clientcerts/client.centminmod.com.pem https://domain.com
```

# Contents


* [Usage](#usage)
* [CA Certificate](#ca-certificate)
* [Server Wildcard SSL Certificate](#server-wildcard-ssl-certificate)
* [Server SSL Certificate](#server-ssl-certificate)
* [Client SSL Certificate](#client-ssl-certificate)
* [Peer Wildcard SSL Certificate](#peer-wildcard-ssl-certificate)
* [Peer SSL Certificate](#peer-wildcard-ssl-certificate)

# Usage

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh

Usage:

Generate CA certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca domain.com expiryhrs

Generate TLS server certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server domain.com expiryhrs server

Generate TLS server wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server domain.com expiryhrs wildcard

Generate TLS Client certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client domain.com expiryhrs client

Generate TLS Peer certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer domain.com expiryhrs peer

Generate TLS Peer wildcard certificate & keys
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer domain.com expiryhrs wildcard
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

2020/09/12 13:21:33 [INFO] generating a new CA key and certificate from CSR
2020/09/12 13:21:33 [INFO] generate received request
2020/09/12 13:21:33 [INFO] received CSR
2020/09/12 13:21:33 [INFO] generating key: ecdsa-256
2020/09/12 13:21:33 [INFO] encoded CSR
2020/09/12 13:21:33 [INFO] signed certificate with serial number 51979244079705508229190957673967436224750582218

openssl x509 -in centminmod.com-ca.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            09:1a:d4:75:70:73:c7:5e:ee:36:2f:80:64:b3:e7:45:37:1e:79:ca
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:17:00 2020 GMT
            Not After : Sep 10 13:17:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=CA, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:4e:ee:8e:7c:1a:49:c4:dd:42:28:f4:f9:a4:f5:
                    fa:c0:d3:f5:87:ea:56:1f:86:64:a9:40:93:63:61:
                    99:d4:d1:ad:bd:d3:4e:8e:53:bb:88:4b:da:5f:00:
                    5d:94:8b:e7:a9:80:76:ed:ac:29:2f:da:8a:1f:05:
                    61:38:24:90:09
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                AC:2E:E5:D7:4F:FD:74:2B:1A:F2:CC:CB:9E:5D:BC:A1:28:74:8D:57
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:03:ce:6b:74:3d:13:b8:52:84:55:9f:fe:96:80:
         7a:c3:46:5c:32:de:cc:58:ee:c8:72:b7:b5:d3:1d:21:fb:d9:
         02:21:00:90:58:cc:29:77:01:70:03:58:8c:1c:56:06:91:56:
         0e:95:3f:53:48:32:f8:ba:b3:90:db:d3:2f:54:23:d0:b1

ca cert: /etc/cfssl/centminmod.com-ca.pem
ca key: /etc/cfssl/centminmod.com-ca-key.pem
ca csr: /etc/cfssl/centminmod.com-ca.csr
ca csr profile: /etc/cfssl/centminmod.com-ca.csr.json
ca profile: /etc/cfssl/profile.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "CA",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "CA",
      "centminmod.com"
    ]
  },
  "serial_number": "51979244079705508229190957673967436224750582218",
  "not_before": "2020-09-12T13:17:00Z",
  "not_after": "2030-09-10T13:17:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "AC:2E:E5:D7:4F:FD:74:2B:1A:F2:CC:CB:9E:5D:BC:A1:28:74:8D:57",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB9DCCAZqgAwIBAgIUCRrUdXBzx17uNi+AZLPnRTceecowCgYIKoZIzj0EAwIw\nWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMQswCQYDVQQLEwJDQTEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wHhcNMjAw\nOTEyMTMxNzAwWhcNMzAwOTEwMTMxNzAwWjBYMQswCQYDVQQGEwJVUzELMAkGA1UE\nCBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xCzAJBgNVBAsTAkNBMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE7u\njnwaScTdQij0+aT1+sDT9YfqVh+GZKlAk2NhmdTRrb3TTo5Tu4hL2l8AXZSL56mA\ndu2sKS/aih8FYTgkkAmjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD\nAQH/MB0GA1UdDgQWBBSsLuXXT/10KxryzMueXbyhKHSNVzAKBggqhkjOPQQDAgNI\nADBFAiADzmt0PRO4UoRVn/6WgHrDRlwy3sxY7shyt7XTHSH72QIhAJBYzCl3AXAD\nWIwcVgaRVg6VP1NIMvi6s5Db0y9UI9Cx\n-----END CERTIFICATE-----\n"
}

--------------------------------------
CA Intermediate generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca-intermediate.csr.json | cfssljson -bare centminmod.com-ca-intermediate

2020/09/12 13:21:33 [INFO] generating a new CA key and certificate from CSR
2020/09/12 13:21:33 [INFO] generate received request
2020/09/12 13:21:33 [INFO] received CSR
2020/09/12 13:21:33 [INFO] generating key: ecdsa-256
2020/09/12 13:21:33 [INFO] encoded CSR
2020/09/12 13:21:33 [INFO] signed certificate with serial number 54924533124229624054260783121466572244774803208

cfssl sign -ca /etc/cfssl/centminmod.com-ca.pem -ca-key /etc/cfssl/centminmod.com-ca-key.pem -config /etc/cfssl/profile.json -profile intermediate_ca centminmod.comca-intermediate.csr | cfssljson -bare centminmod.com-ca-intermediate
2020/09/12 13:21:33 [INFO] signed certificate with serial number 157829954090881895767767084957269407059785675046

openssl x509 -in centminmod.com-ca-intermediate.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1b:a5:57:04:8f:99:37:3a:52:8b:61:68:46:81:21:41:26:d5:f1:26
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:17:00 2020 GMT
            Not After : Sep 10 13:17:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:34:42:57:af:19:97:45:98:d7:55:6f:1f:37:d4:
                    ff:9b:f9:9f:73:ea:9e:89:ab:7c:7b:b7:1a:2c:c0:
                    ea:a4:f9:91:fb:72:bf:be:98:c1:99:86:03:29:b4:
                    5d:2c:7d:31:5d:06:f5:88:d7:10:90:a5:1d:e6:6f:
                    12:9c:e5:a1:de
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
                20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB
            X509v3 Authority Key Identifier: 
                keyid:AC:2E:E5:D7:4F:FD:74:2B:1A:F2:CC:CB:9E:5D:BC:A1:28:74:8D:57

    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:2d:61:48:bf:4a:e0:2f:91:14:6f:0f:f1:9e:c9:
         0d:6b:a8:89:40:89:a1:4c:f3:21:f1:ec:9f:9a:0a:52:15:22:
         02:21:00:da:95:a6:af:a0:fd:ee:4f:76:52:96:e1:3f:51:02:
         54:d1:d0:f6:2a:65:61:ae:a1:3e:6c:dc:71:b9:00:c6:4a

ca intermediate cert: /etc/cfssl/centminmod.com-ca-intermediate.pem
ca intermediate key: /etc/cfssl/centminmod.com-ca-intermediate-key.pem
ca intermediate csr: /etc/cfssl/centminmod.com-ca-intermediate.csr
ca intermediate csr profile: /etc/cfssl/centminmod.com-ca-intermediate.csr.json
ca intermediate profile: /etc/cfssl/profile.json

{
  "subject": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "issuer": {
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "CA",
      "centminmod.com"
    ]
  },
  "serial_number": "157829954090881895767767084957269407059785675046",
  "not_before": "2020-09-12T13:17:00Z",
  "not_after": "2030-09-10T13:17:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "AC:2E:E5:D7:4F:FD:74:2B:1A:F2:CC:CB:9E:5D:BC:A1:28:74:8D:57",
  "subject_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRjCCAeygAwIBAgIUG6VXBI+ZNzpSi2FoRoEhQSbV8SYwCgYIKoZIzj0EAwIw\nWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMQswCQYDVQQLEwJDQTEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wHhcNMjAw\nOTEyMTMxNzAwWhcNMzAwOTEwMTMxNzAwWjBlMQswCQYDVQQGEwJVUzELMAkGA1UE\nCBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xGDAWBgNVBAsTD0ludGVybWVk\naWF0ZSBDQTEXMBUGA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggq\nhkjOPQMBBwNCAAQ0QlevGZdFmNdVbx831P+b+Z9z6p6Jq3x7txoswOqk+ZH7cr++\nmMGZhgMptF0sfTFdBvWI1xCQpR3mbxKc5aHeo4GGMIGDMA4GA1UdDwEB/wQEAwIB\npjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB\n/wIBADAdBgNVHQ4EFgQUICnDK+xdQIxvMK3oAIVcL6Eet+swHwYDVR0jBBgwFoAU\nrC7l10/9dCsa8szLnl28oSh0jVcwCgYIKoZIzj0EAwIDSAAwRQIgLWFIv0rgL5EU\nbw/xnskNa6iJQImhTPMh8eyfmgpSFSICIQDalaavoP3uT3ZSluE/UQJU0dD2KmVh\nrqE+bNxxuQDGSg==\n-----END CERTIFICATE-----\n"
}

CA Bundle generated: /etc/cfssl/centminmod.com-ca-bundle.pem

cat /etc/cfssl/centminmod.com-ca.pem /etc/cfssl/centminmod.com-ca-intermediate.pem > /etc/cfssl/centminmod.com-ca-bundle.pem
```

# Server Wildcard SSL Certificate

Generate self-signed server wildcard SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication` using `wildcard` option.

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 wildcard

cfssl gencert -config /etc/cfssl/profile.json -profile server -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:22:33 [INFO] generate received request
2020/09/12 13:22:33 [INFO] received CSR
2020/09/12 13:22:33 [INFO] generating key: ecdsa-256
2020/09/12 13:22:33 [INFO] encoded CSR
2020/09/12 13:22:33 [INFO] signed certificate with serial number 179782923004220395668081928492668890196493523529

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1f:7d:be:bd:ea:19:4a:08:aa:27:a8:6a:09:a9:ed:89:c4:ec:da:49
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:18:00 2020 GMT
            Not After : Sep 10 13:18:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:d0:d2:b7:1b:49:d5:23:48:55:c7:14:32:e2:e0:
                    92:d3:bf:dc:be:0e:f7:e8:67:1b:10:4e:8d:30:b8:
                    e5:81:31:38:87:b7:f0:23:bf:93:4c:b2:94:56:a7:
                    f5:c8:fd:9b:a1:f0:92:0a:27:78:39:22:3c:eb:c4:
                    8d:67:c0:ac:cb
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
                15:23:46:8D:98:0E:79:7E:05:36:40:17:7F:FE:F7:2A:7C:06:33:3A
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:a4:07:f6:c6:0f:e3:19:4e:9b:6e:31:0c:c3:
         12:fd:be:61:f1:4b:30:9c:af:84:45:16:24:3d:85:b7:84:07:
         93:02:21:00:f5:0c:d8:74:cc:76:7d:d4:36:2b:dc:d6:31:3d:
         00:a7:c7:2d:05:92:92:82:82:6c:f6:10:53:8d:c2:91:ef:fe

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
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "179782923004220395668081928492668890196493523529",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T13:18:00Z",
  "not_after": "2030-09-10T13:18:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "15:23:46:8D:98:0E:79:7E:05:36:40:17:7F:FE:F7:2A:7C:06:33:3A",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICVzCCAfygAwIBAgIUH32+veoZSgiqJ6hqCanticTs2kkwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMTgwMFoXDTMwMDkxMDEzMTgwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNDS\ntxtJ1SNIVccUMuLgktO/3L4O9+hnGxBOjTC45YExOIe38CO/k0yylFan9cj9m6Hw\nkgoneDkiPOvEjWfArMujgaMwgaAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG\nCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBUjRo2YDnl+BTZAF3/+\n9yp8BjM6MB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACFXC+hHrfrMCsGA1UdEQQk\nMCKCDmNlbnRtaW5tb2QuY29tghAqLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMC\nA0kAMEYCIQCkB/bGD+MZTptuMQzDEv2+YfFLMJyvhEUWJD2Ft4QHkwIhAPUM2HTM\ndn3UNivc1jE9AKfHLQWSkoKCbPYQU43Cke/+\n-----END CERTIFICATE-----\n"
}
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:23:14 [INFO] generate received request
2020/09/12 13:23:14 [INFO] received CSR
2020/09/12 13:23:14 [INFO] generating key: ecdsa-256
2020/09/12 13:23:14 [INFO] encoded CSR
2020/09/12 13:23:14 [INFO] signed certificate with serial number 603573150065020846116360668497768876574050440426

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            69:b9:27:f6:86:0b:6f:91:ae:9f:5b:87:85:d5:a4:ff:8b:09:54:ea
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:18:00 2020 GMT
            Not After : Sep 10 13:18:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:56:b3:c3:da:35:e4:34:6e:69:c5:9a:f3:70:f6:
                    44:ff:1d:69:2c:33:c8:6d:7e:62:8f:4e:27:c5:a5:
                    3f:53:76:b2:19:a6:30:4e:7f:fa:a2:dc:75:9c:4f:
                    c1:c2:66:64:79:f4:47:8c:3c:1a:b6:a4:01:9f:8f:
                    b7:06:40:46:54
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
                8D:E5:65:B1:09:EF:9B:7D:DD:F6:6A:54:4A:F4:82:A7:3C:79:6E:52
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:e1:10:4d:40:83:b6:4d:4d:81:71:7c:18:a9:
         f2:46:bd:88:84:2d:3e:47:09:90:13:13:6a:a7:8e:00:dc:70:
         f8:02:21:00:9f:7f:52:96:3e:ce:cb:2e:78:3e:99:6e:34:d8:
         86:0f:2c:54:1e:2c:9a:ed:42:ca:de:b4:83:1f:d5:b0:7c:56

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
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "603573150065020846116360668497768876574050440426",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T13:18:00Z",
  "not_after": "2030-09-10T13:18:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "8D:E5:65:B1:09:EF:9B:7D:DD:F6:6A:54:4A:F4:82:A7:3C:79:6E:52",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeqgAwIBAgIUabkn9oYLb5Gun1uHhdWk/4sJVOowCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMTgwMFoXDTMwMDkxMDEzMTgwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFaz\nw9o15DRuacWa83D2RP8daSwzyG1+Yo9OJ8WlP1N2shmmME5/+qLcdZxPwcJmZHn0\nR4w8GrakAZ+PtwZARlSjgZEwgY4wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG\nCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFI3lZbEJ75t93fZqVEr0\ngqc8eW5SMB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACFXC+hHrfrMBkGA1UdEQQS\nMBCCDmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDhEE1Ag7ZNTYFx\nfBip8ka9iIQtPkcJkBMTaqeOANxw+AIhAJ9/UpY+zssueD6ZbjTYhg8sVB4smu1C\nyt60gx/VsHxW\n-----END CERTIFICATE-----\n"
}
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn server.centminmod.com -hostname server.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem server.centminmod.com.csr.json > server.centminmod.com.json
2020/09/12 13:23:57 [INFO] generate received request
2020/09/12 13:23:57 [INFO] received CSR
2020/09/12 13:23:57 [INFO] generating key: ecdsa-256
2020/09/12 13:23:57 [INFO] encoded CSR
2020/09/12 13:23:57 [INFO] signed certificate with serial number 130338219757322254164091633097459462239291093100

cfssljson -f server.centminmod.com.json -bare server.centminmod.com


openssl x509 -in server.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            16:d4:91:62:8d:6b:18:f0:f2:a7:7e:68:9f:14:71:1b:2a:2a:b0:6c
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:19:00 2020 GMT
            Not After : Sep 10 13:19:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:e9:11:94:43:93:2c:39:75:22:3a:2b:c0:5f:c4:
                    36:86:f5:05:2c:95:73:db:1d:7e:e3:7b:e6:3d:8b:
                    03:c7:e7:31:31:b3:ae:04:45:15:18:50:64:3e:f9:
                    90:99:b9:aa:25:44:c9:45:69:ae:73:93:ef:3f:3e:
                    a0:93:5b:8a:3d
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
                8D:51:02:DA:58:1A:15:C8:03:30:FB:41:F2:38:70:AA:76:2D:1C:9B
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:0b:48:09:00:7e:29:cd:ce:8c:fa:a5:06:6b:35:
         5c:be:7d:bc:1b:06:a7:e8:5b:f0:65:5e:cc:a9:9b:f9:15:d4:
         02:20:2a:23:26:0c:e7:da:ae:03:13:af:d7:db:40:9b:35:1b:
         5e:41:69:6d:47:f5:5a:9e:15:0f:47:37:79:ab:e4:24

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
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "130338219757322254164091633097459462239291093100",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-12T13:19:00Z",
  "not_after": "2030-09-10T13:19:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "8D:51:02:DA:58:1A:15:C8:03:30:FB:41:F2:38:70:AA:76:2D:1C:9B",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICUTCCAfigAwIBAgIUFtSRYo1rGPDyp35onxRxGyoqsGwwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMTkwMFoXDTMwMDkxMDEzMTkwMFowUjELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR4wHAYD\nVQQDExVzZXJ2ZXIuY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMB\nBwNCAATpEZRDkyw5dSI6K8BfxDaG9QUslXPbHX7je+Y9iwPH5zExs64ERRUYUGQ+\n+ZCZuaolRMlFaa5zk+8/PqCTW4o9o4GYMIGVMA4GA1UdDwEB/wQEAwIFoDATBgNV\nHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSNUQLaWBoV\nyAMw+0HyOHCqdi0cmzAfBgNVHSMEGDAWgBQgKcMr7F1AjG8wregAhVwvoR636zAg\nBgNVHREEGTAXghVzZXJ2ZXIuY2VudG1pbm1vZC5jb20wCgYIKoZIzj0EAwIDRwAw\nRAIgC0gJAH4pzc6M+qUGazVcvn28Gwan6FvwZV7MqZv5FdQCICojJgzn2q4DE6/X\n20CbNRteQWltR/VanhUPRzd5q+Qk\n-----END CERTIFICATE-----\n"
}
```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:24:21 [INFO] generate received request
2020/09/12 13:24:21 [INFO] received CSR
2020/09/12 13:24:21 [INFO] generating key: ecdsa-256
2020/09/12 13:24:21 [INFO] encoded CSR
2020/09/12 13:24:21 [INFO] signed certificate with serial number 311158108511348429990385192663569657418975761036

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            36:80:cf:e8:eb:49:e0:c9:54:86:7b:a5:2d:7d:fb:12:92:b3:52:8c
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:19:00 2020 GMT
            Not After : Sep 10 13:19:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:3b:a9:1b:bc:05:25:4c:5c:c2:e6:76:b8:02:40:
                    4b:fa:9b:7c:5e:13:8a:c9:42:bf:2e:3a:4d:9a:f0:
                    16:27:0e:5a:29:72:38:bc:7b:ed:f6:e9:4a:7f:3e:
                    a9:a5:19:29:40:28:c0:2f:0e:3d:13:6b:60:e0:ef:
                    82:fe:cc:8d:cc
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                98:72:D3:0D:FA:33:43:A6:72:A9:A9:1C:12:C4:60:97:8F:39:02:6B
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:25:bf:51:ef:13:84:d7:66:75:9c:f0:7a:da:c5:
         45:c0:fe:bf:36:01:19:9d:38:27:4c:9f:7d:ee:4d:1e:02:54:
         02:20:0c:b4:9a:2b:94:35:dc:b7:65:91:73:f3:21:d1:20:74:
         3d:60:20:b9:eb:ce:14:d3:09:82:3f:54:ce:81:a3:28

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
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "311158108511348429990385192663569657418975761036",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-12T13:19:00Z",
  "not_after": "2030-09-10T13:19:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "98:72:D3:0D:FA:33:43:A6:72:A9:A9:1C:12:C4:60:97:8F:39:02:6B",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICQzCCAeqgAwIBAgIUNoDP6OtJ4MlUhnulLX37EpKzUowwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMTkwMFoXDTMwMDkxMDEzMTkwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDup\nG7wFJUxcwuZ2uAJAS/qbfF4TislCvy46TZrwFicOWilyOLx77fbpSn8+qaUZKUAo\nwC8OPRNrYODvgv7MjcyjgZEwgY4wDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG\nCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFJhy0w36M0OmcqmpHBLE\nYJePOQJrMB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACFXC+hHrfrMBkGA1UdEQQS\nMBCCDmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0cAMEQCICW/Ue8ThNdmdZzw\netrFRcD+vzYBGZ04J0yffe5NHgJUAiAMtJorlDXct2WRc/Mh0SB0PWAguevOFNMJ\ngj9UzoGjKA==\n-----END CERTIFICATE-----\n"
}

```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn client.centminmod.com -hostname client.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem client.centminmod.com.csr.json > client.centminmod.com.json
2020/09/12 13:05:09 [INFO] generate received request
2020/09/12 13:05:09 [INFO] received CSR
2020/09/12 13:05:09 [INFO] generating key: ecdsa-256
2020/09/12 13:05:09 [INFO] encoded CSR
2020/09/12 13:05:09 [INFO] signed certificate with serial number 195215568395031250743425933051693886324494469655

cfssljson -f client.centminmod.com.json -bare client.centminmod.com


openssl x509 -in client.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            22:31:c4:d2:9a:30:84:72:e2:1d:1b:6e:e9:61:5f:cc:65:0a:8a:17
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:00:00 2020 GMT
            Not After : Sep 10 13:00:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:e7:54:57:fb:e7:84:af:1a:13:8e:21:d6:3c:53:
                    0c:d1:2c:c0:ce:ed:9a:b2:79:96:c4:bc:2a:96:49:
                    ee:78:64:ff:66:d0:97:05:77:86:38:96:37:c9:f8:
                    d1:64:03:de:8f:57:38:95:38:fb:0e:8c:2c:42:a3:
                    a4:8c:07:30:8d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                AD:B7:CB:B5:9E:56:AC:DB:76:4A:AB:D0:A4:8E:CF:FC:32:82:45:8F
            X509v3 Authority Key Identifier: 
                keyid:EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:f6:aa:30:69:65:98:21:3f:b7:a8:a2:54:a3:
         cd:f6:1f:1d:78:f3:91:42:0b:ef:5a:07:e4:3f:4d:02:96:13:
         8d:02:21:00:e7:25:75:86:1f:f1:f2:73:24:ef:61:47:df:3e:
         7c:a6:f1:5d:8d:b0:05:33:ec:9a:22:aa:56:2e:23:13:8f:1e

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
  "serial_number": "195215568395031250743425933051693886324494469655",
  "sans": [
    "client.centminmod.com"
  ],
  "not_before": "2020-09-12T13:00:00Z",
  "not_after": "2030-09-10T13:00:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "EB:26:7F:00:60:EA:2D:2B:44:F1:46:D8:A3:BF:91:3A:DE:BF:B9:07",
  "subject_key_id": "AD:B7:CB:B5:9E:56:AC:DB:76:4A:AB:D0:A4:8E:CF:FC:32:82:45:8F",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICOTCCAd6gAwIBAgIUIjHE0powhHLiHRtu6WFfzGUKihcwCgYIKoZIzj0EAwIw\nSzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRcwFQYDVQQDEw5jZW50bWlubW9kLmNvbTAeFw0yMDA5MTIxMzAwMDBaFw0z\nMDA5MTAxMzAwMDBaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE\nBxMNU2FuIEZyYW5jaXNjbzEeMBwGA1UEAxMVY2xpZW50LmNlbnRtaW5tb2QuY29t\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE51RX++eErxoTjiHWPFMM0SzAzu2a\nsnmWxLwqlknueGT/ZtCXBXeGOJY3yfjRZAPej1c4lTj7DowsQqOkjAcwjaOBmDCB\nlTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/\nBAIwADAdBgNVHQ4EFgQUrbfLtZ5WrNt2SqvQpI7P/DKCRY8wHwYDVR0jBBgwFoAU\n6yZ/AGDqLStE8UbYo7+ROt6/uQcwIAYDVR0RBBkwF4IVY2xpZW50LmNlbnRtaW5t\nb2QuY29tMAoGCCqGSM49BAMCA0kAMEYCIQD2qjBpZZghP7eoolSjzfYfHXjzkUIL\n71oH5D9NApYTjQIhAOcldYYf8fJzJO9hR98+fKbxXY2wBTPsmiKqVi4jE48e\n-----END CERTIFICATE-----\n"
}
```

# Peer Wildcard SSL Certificate

Generate self-signed peer wildcard SSL certificate with CA signing for centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 wildcard

cfssl gencert -config /etc/cfssl/profile.json -profile peer -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/12 13:24:45 [INFO] generate received request
2020/09/12 13:24:45 [INFO] received CSR
2020/09/12 13:24:45 [INFO] generating key: ecdsa-256
2020/09/12 13:24:45 [INFO] encoded CSR
2020/09/12 13:24:45 [INFO] signed certificate with serial number 232608356446407482356852142634287709643919817920

cfssljson -f centminmod.com.json -bare centminmod.com


openssl x509 -in centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            28:be:84:fa:64:5b:96:f5:7c:68:bc:ad:29:ae:f6:74:92:b3:7c:c0
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:20:00 2020 GMT
            Not After : Sep 10 13:20:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:dc:20:f7:00:b8:ec:cc:b5:73:52:46:c8:30:36:
                    ef:77:fd:d2:70:d3:7a:69:df:b8:ba:b7:d8:73:05:
                    ad:a5:44:1a:39:51:4f:80:53:cf:67:d0:6b:1c:ca:
                    14:be:e3:6a:78:c0:81:7a:0b:da:2b:5a:87:05:bd:
                    4d:c5:f8:e5:43
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
                2A:64:75:B9:B0:1B:1D:DA:68:BF:8A:56:B6:09:21:2A:1C:F9:69:42
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:6e:c1:8f:4c:5a:65:5b:06:e9:be:e4:5e:38:19:
         86:17:64:ea:81:1d:c8:4e:36:32:e7:41:41:53:a2:57:05:f1:
         02:21:00:9f:91:62:92:88:38:cd:44:0b:5c:0e:9a:c5:d9:36:
         fd:e0:71:7c:14:b0:4a:04:75:a7:85:19:5d:00:07:fc:ad

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
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "232608356446407482356852142634287709643919817920",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-12T13:20:00Z",
  "not_after": "2030-09-10T13:20:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "2A:64:75:B9:B0:1B:1D:DA:68:BF:8A:56:B6:09:21:2A:1C:F9:69:42",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICYDCCAgagAwIBAgIUKL6E+mRblvV8aLytKa72dJKzfMAwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMjAwMFoXDTMwMDkxMDEzMjAwMFowSzELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRcwFQYD\nVQQDEw5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNwg\n9wC47My1c1JGyDA273f90nDTemnfuLq32HMFraVEGjlRT4BTz2fQaxzKFL7janjA\ngXoL2itahwW9TcX45UOjga0wgaowDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG\nCCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQqZHW5\nsBsd2mi/ila2CSEqHPlpQjAfBgNVHSMEGDAWgBQgKcMr7F1AjG8wregAhVwvoR63\n6zArBgNVHREEJDAigg5jZW50bWlubW9kLmNvbYIQKi5jZW50bWlubW9kLmNvbTAK\nBggqhkjOPQQDAgNIADBFAiBuwY9MWmVbBum+5F44GYYXZOqBHchONjLnQUFTolcF\n8QIhAJ+RYpKIOM1EC1wOmsXZNv3gcXwUsEoEdaeFGV0AB/yt\n-----END CERTIFICATE-----\n"
}

```

# Peer SSL Certificate

Generate self-signed peer SSL certificate with CA signing for peer.centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 peer

cfssl gencert -config /etc/cfssl/profile.json -profile peer -cn peer.centminmod.com -hostname peer.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem peer.centminmod.com.csr.json > peer.centminmod.com.json
2020/09/12 13:25:13 [INFO] generate received request
2020/09/12 13:25:13 [INFO] received CSR
2020/09/12 13:25:13 [INFO] generating key: ecdsa-256
2020/09/12 13:25:13 [INFO] encoded CSR
2020/09/12 13:25:13 [INFO] signed certificate with serial number 32139185138931896287904597157203112385066954644

cfssljson -f peer.centminmod.com.json -bare peer.centminmod.com


openssl x509 -in peer.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            05:a1:2b:c0:6d:57:6b:1c:56:42:b1:0d:45:08:26:07:cc:d9:ef:94
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=centminmod.com
        Validity
            Not Before: Sep 12 13:20:00 2020 GMT
            Not After : Sep 10 13:20:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=peer.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:b2:9b:d8:46:9d:f2:82:07:ae:ed:ec:1e:a1:4c:
                    80:64:91:e9:58:ea:52:0a:45:af:17:72:aa:7c:3e:
                    03:5c:1d:dd:dd:d2:71:7e:be:de:67:da:a3:7c:e4:
                    59:dc:f0:a8:1c:c3:69:a4:c6:d5:65:e3:a6:46:a7:
                    51:4d:be:a2:a1
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
                2B:64:41:35:D9:D8:F1:03:54:FE:BD:A1:61:BB:91:8A:CF:D7:76:1F
            X509v3 Authority Key Identifier: 
                keyid:20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB

            X509v3 Subject Alternative Name: 
                DNS:peer.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:e5:f8:0c:51:1b:04:9d:ab:4b:e4:a9:94:f5:
         07:77:c0:bf:9e:89:03:36:68:d5:02:01:7f:a8:5f:32:e4:aa:
         88:02:21:00:d1:73:36:72:9f:b3:e9:39:7b:8b:29:ba:7c:01:
         c0:f5:ea:56:3e:d1:39:e6:be:11:36:11:c4:e6:55:a4:44:1d

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
    "common_name": "centminmod.com",
    "country": "US",
    "organizational_unit": "Intermediate CA",
    "locality": "San Francisco",
    "province": "CA",
    "names": [
      "US",
      "CA",
      "San Francisco",
      "Intermediate CA",
      "centminmod.com"
    ]
  },
  "serial_number": "32139185138931896287904597157203112385066954644",
  "sans": [
    "peer.centminmod.com"
  ],
  "not_before": "2020-09-12T13:20:00Z",
  "not_after": "2030-09-10T13:20:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "20:29:C3:2B:EC:5D:40:8C:6F:30:AD:E8:00:85:5C:2F:A1:1E:B7:EB",
  "subject_key_id": "2B:64:41:35:D9:D8:F1:03:54:FE:BD:A1:61:BB:91:8A:CF:D7:76:1F",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICWTCCAf6gAwIBAgIUBaErwG1XaxxWQrENRQgmB8zZ75QwCgYIKoZIzj0EAwIw\nZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExFzAVBgNVBAMTDmNlbnRtaW5t\nb2QuY29tMB4XDTIwMDkxMjEzMjAwMFoXDTMwMDkxMDEzMjAwMFowUDELMAkGA1UE\nBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRwwGgYD\nVQQDExNwZWVyLmNlbnRtaW5tb2QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\nQgAEspvYRp3yggeu7eweoUyAZJHpWOpSCkWvF3KqfD4DXB3d3dJxfr7eZ9qjfORZ\n3PCoHMNppMbVZeOmRqdRTb6ioaOBoDCBnTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\nBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYE\nFCtkQTXZ2PEDVP69oWG7kYrP13YfMB8GA1UdIwQYMBaAFCApwyvsXUCMbzCt6ACF\nXC+hHrfrMB4GA1UdEQQXMBWCE3BlZXIuY2VudG1pbm1vZC5jb20wCgYIKoZIzj0E\nAwIDSQAwRgIhAOX4DFEbBJ2rS+SplPUHd8C/nokDNmjVAgF/qF8y5KqIAiEA0XM2\ncp+z6Tl7iym6fAHA9epWPtE55r4RNhHE5lWkRB0=\n-----END CERTIFICATE-----\n"
}
```