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

There are 4 options

* `gen-ca` - used to generate the CA Root and CA Intermediate certificates where CA Intermediate is signed by CA Root and it accepts 2 arguments. 
  * First argument is the intended CA domain prefix label for the certificates - specify centminmod.com would label name certs as `/etc/cfssl/centminmod.com-ca.pem`, `/etc/cfssl/centminmod.com-ca-intermediate.pem` and bundle as `/etc/cfssl/centminmod.com-ca-bundle.pem`.
  * The second argument is how long the certificate expiry is in hours i.e. 87600 hrs = 10 yrs, 43800 hrs = 5 yrs. This allows for creating multiple CA Root/CA Intermediate/CA Bundle grouped by domain file name.
* `gen-server` - used to generate server self-signed SSL certificates with x509v3 Extended Key Usage = `TLS Web Server Authentication`.
  * First argument defines the CA Intermediate prefix labeled domain defined which is used to sign the server self-signed SSL certificate.
  * The second argument is how long the certificate expiry is in hours i.e. 87600 hrs = 10 yrs, 43800 hrs = 5 yrs. 
  * The third argument defines a subdomain name or special `wildcard` option - which when specified adds `*.domain.com` to the certificate SANs (Subject Alternative Name) entries. Example at [Server Wildcard SSL Certificate](#server-wildcard-ssl-certificate).
  * The forth argument is the intended domain name for self-signed SSL certificate.
  * You need to have prior ran the `gen-ca` option for this option to work as it needs the CA Intermediate certificate to sign the server self-signed SSL certificate.
* `gen-client` - used to generate client self-signed SSL certificates with x509v3 Extended Key Usage = `TLS Web Client Authentication`. Full example shown below in [Browser Client TLS Authentication](#browser-client-tls-authentication) and [Curl Client TLS Authentication](#curl-client-tls-authentication) sections.
  * First argument defines the CA Intermediate prefix labeled domain defined which is used to sign the server self-signed SSL certificate.
  * The second argument is how long the certificate expiry is in hours i.e. 87600 hrs = 10 yrs, 43800 hrs = 5 yrs. 
  * The third argument defines a subdomain name.
  * The forth argument is the intended domain name for self-signed SSL certificate.
  * You need to have prior ran the `gen-ca` option for this option to work as it needs the CA Intermediate certificate to sign the client self-signed SSL certificate.
* `gen-peer` - used to generate peer self-signed SSL certificates with x509v3 Extended Key Usage = `TLS Web Server Authentication` + `TLS Web Client Authentication`.
  * First argument defines the CA Intermediate prefix labeled domain defined which is used to sign the server self-signed SSL certificate.
  * The second argument is how long the certificate expiry is in hours i.e. 87600 hrs = 10 yrs, 43800 hrs = 5 yrs. 
  * The third argument defines a subdomain name or special `wildcard` option - which when specified adds `*.domain.com` to the certificate SANs (Subject Alternative Name) entries. Example at [Peer Wildcard SSL Certificate](#peer-wildcard-ssl-certificate).
  * The forth argument is the intended domain name for self-signed SSL certificate.
  * You need to have prior ran the `gen-ca` option for this option to work as it needs the CA Intermediate certificate to sign the peer self-signed SSL certificate.

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
* CA certificate private key /etc/cfssl/centminmod.com-ca-key.pem
* CA certificate public key /etc/cfssl/centminmod.com-ca-publickey.pem
* CA Intermediate certificate /etc/cfssl/centminmod.com-ca-intermediate.pem
* CA Intermediate certificate private key /etc/cfssl/centminmod.com-ca-intermediate-key.pem
* CA Intermediate certificate public key /etc/cfssl/centminmod.com-ca-intermediate-publickey.pem
* CA Bundle certificate /etc/cfssl/centminmod.com-ca-bundle.pem

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-ca centminmod.com 87600
--------------------------------------
CA generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca.csr.json | cfssljson -bare centminmod.com-ca

2020/09/15 04:31:34 [INFO] generating a new CA key and certificate from CSR
2020/09/15 04:31:34 [INFO] generate received request
2020/09/15 04:31:34 [INFO] received CSR
2020/09/15 04:31:34 [INFO] generating key: ecdsa-256
2020/09/15 04:31:34 [INFO] encoded CSR
2020/09/15 04:31:34 [INFO] signed certificate with serial number 686727792341884987952702873227439390181235858982

openssl x509 -in /etc/cfssl/centminmod.com-ca.pem -text -noout

Extract CA Root certicate public key: /etc/cfssl/centminmod.com-ca-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/centminmod.com-ca.pem > /etc/cfssl/centminmod.com-ca-publickey.pem
cat /etc/cfssl/centminmod.com-ca-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECJ2jViJih2HZQqgx38O7psazhDWn
gM5jxVmbfjfyecQYCDkUhdYhZr2ym/D74sG9aeL3kzvb8mANiNMsfKkQZw==
-----END PUBLIC KEY-----

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            78:49:f0:71:20:59:94:a3:6d:41:9f:ee:0d:dc:d3:37:51:a7:9e:26
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=Root CA
        Validity
            Not Before: Sep 15 04:27:00 2020 GMT
            Not After : Sep 13 04:27:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:08:9d:a3:56:22:62:87:61:d9:42:a8:31:df:c3:
                    bb:a6:c6:b3:84:35:a7:80:ce:63:c5:59:9b:7e:37:
                    f2:79:c4:18:08:39:14:85:d6:21:66:bd:b2:9b:f0:
                    fb:e2:c1:bd:69:e2:f7:93:3b:db:f2:60:0d:88:d3:
                    2c:7c:a9:10:67
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                AF:7E:B8:E6:E0:47:22:71:FC:94:74:DF:9E:50:B2:0A:C2:76:D1:44
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:ed:f5:c2:b0:7d:96:4e:59:b5:85:80:b6:7f:
         e1:55:42:ad:85:15:36:c2:2f:3d:93:24:7c:35:c2:cd:84:48:
         f8:02:21:00:c9:18:28:f7:35:91:fc:d0:b9:85:f9:a2:73:66:
         a8:7c:fb:67:de:2f:2c:1f:aa:c4:50:63:38:95:15:58:c2:a5

ca cert: /etc/cfssl/centminmod.com-ca.pem
ca private key: /etc/cfssl/centminmod.com-ca-key.pem
ca public key: /etc/cfssl/centminmod.com-ca-publickey.pem
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
  "serial_number": "686727792341884987952702873227439390181235858982",
  "not_before": "2020-09-15T04:27:00Z",
  "not_after": "2030-09-13T04:27:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "",
  "subject_key_id": "AF:7E:B8:E6:E0:47:22:71:FC:94:74:DF:9E:50:B2:0A:C2:76:D1:44",
  "pem": "-----BEGIN CERTIFICATE-----\nMIIB8TCCAZagAwIBAgIUeEnwcSBZlKNtQZ/uDdzTN1GnniYwCgYIKoZIzj0EAwIw\nVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRAwDgYDVQQLEwdSb290IENBMRAwDgYDVQQDEwdSb290IENBMB4XDTIwMDkx\nNTA0MjcwMFoXDTMwMDkxMzA0MjcwMFowVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgT\nAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRAwDgYDVQQLEwdSb290IENBMRAw\nDgYDVQQDEwdSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECJ2jViJi\nh2HZQqgx38O7psazhDWngM5jxVmbfjfyecQYCDkUhdYhZr2ym/D74sG9aeL3kzvb\n8mANiNMsfKkQZ6NCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w\nHQYDVR0OBBYEFK9+uObgRyJx/JR0355QsgrCdtFEMAoGCCqGSM49BAMCA0kAMEYC\nIQDt9cKwfZZOWbWFgLZ/4VVCrYUVNsIvPZMkfDXCzYRI+AIhAMkYKPc1kfzQuYX5\nonNmqHz7Z94vLB+qxFBjOJUVWMKl\n-----END CERTIFICATE-----\n"
}

--------------------------------------
CA Intermediate generation
--------------------------------------

cfssl gencert -initca centminmod.com-ca-intermediate.csr.json | cfssljson -bare centminmod.com-ca-intermediate

2020/09/15 04:31:34 [INFO] generating a new CA key and certificate from CSR
2020/09/15 04:31:34 [INFO] generate received request
2020/09/15 04:31:34 [INFO] received CSR
2020/09/15 04:31:34 [INFO] generating key: ecdsa-256
2020/09/15 04:31:34 [INFO] encoded CSR
2020/09/15 04:31:34 [INFO] signed certificate with serial number 563144683109045093924274326758394013884429079825

cfssl sign -ca /etc/cfssl/centminmod.com-ca.pem -ca-key /etc/cfssl/centminmod.com-ca-key.pem -config /etc/cfssl/profile.json -profile intermediate_ca centminmod.comca-intermediate.csr | cfssljson -bare centminmod.com-ca-intermediate
2020/09/15 04:31:34 [INFO] signed certificate with serial number 236486850035850570205586586246618168815674568042

openssl x509 -in centminmod.com-ca-intermediate.pem -text -noout

Extract CA Intermediate certicate public key: /etc/cfssl/centminmod.com-ca-intermediate-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/centminmod.com-ca-intermediate.pem > /etc/cfssl/centminmod.com-ca-intermediate-publickey.pem
cat /etc/cfssl/centminmod.com-ca-intermediate-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpEW5geBSvpWNKfPEEeubYWO6TYcN
KYvj4iB6yKNJf45p4a424GoL8+Fxww1HiJlLCmpu3s/d/627NEUA394NqA==
-----END PUBLIC KEY-----

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            29:6c:6f:e6:a6:f9:d3:cf:09:04:08:49:07:3f:9c:84:83:d9:ad:6a
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Root CA, CN=Root CA
        Validity
            Not Before: Sep 15 04:27:00 2020 GMT
            Not After : Sep 13 04:27:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:a4:45:b9:81:e0:52:be:95:8d:29:f3:c4:11:eb:
                    9b:61:63:ba:4d:87:0d:29:8b:e3:e2:20:7a:c8:a3:
                    49:7f:8e:69:e1:ae:36:e0:6a:0b:f3:e1:71:c3:0d:
                    47:88:99:4b:0a:6a:6e:de:cf:dd:ff:ad:bb:34:45:
                    00:df:de:0d:a8
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
                81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8
            X509v3 Authority Key Identifier: 
                keyid:AF:7E:B8:E6:E0:47:22:71:FC:94:74:DF:9E:50:B2:0A:C2:76:D1:44

    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:34:e2:0b:9a:99:69:57:74:93:73:95:41:91:25:
         46:a7:77:f9:c3:3f:ef:99:c0:3e:56:05:f3:b1:50:c6:0e:86:
         02:21:00:d5:57:b5:0c:ff:df:65:65:23:ae:56:5a:2d:6f:9e:
         26:3d:f9:7d:2e:7a:5b:e8:83:b8:4d:e1:14:1e:fb:be:51

ca intermediate cert: /etc/cfssl/centminmod.com-ca-intermediate.pem
ca intermediate private key: /etc/cfssl/centminmod.com-ca-intermediate-key.pem
ca intermediate public key: /etc/cfssl/centminmod.com-ca-intermediate-publickey.pem
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
  "serial_number": "236486850035850570205586586246618168815674568042",
  "not_before": "2020-09-15T04:27:00Z",
  "not_after": "2030-09-13T04:27:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "AF:7E:B8:E6:E0:47:22:71:FC:94:74:DF:9E:50:B2:0A:C2:76:D1:44",
  "subject_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIUKWxv5qb5088JBAhJBz+chIPZrWowCgYIKoZIzj0EAwIw\nVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRAwDgYDVQQLEwdSb290IENBMRAwDgYDVQQDEwdSb290IENBMB4XDTIwMDkx\nNTA0MjcwMFoXDTMwMDkxMzA0MjcwMFowZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgT\nAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlh\ndGUgQ0ExGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABKRFuYHgUr6VjSnzxBHrm2Fjuk2HDSmL4+IgesijSX+OaeGuNuBq\nC/PhccMNR4iZSwpqbt7P3f+tuzRFAN/eDaijgYYwgYMwDgYDVR0PAQH/BAQDAgGm\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjASBgNVHRMBAf8ECDAGAQH/\nAgEAMB0GA1UdDgQWBBSBaRVXvWz+5Ig9qon7MIoCUrYw6DAfBgNVHSMEGDAWgBSv\nfrjm4EcicfyUdN+eULIKwnbRRDAKBggqhkjOPQQDAgNIADBFAiA04guamWlXdJNz\nlUGRJUand/nDP++ZwD5WBfOxUMYOhgIhANVXtQz/32VlI65WWi1vniY9+X0uelvo\ng7hN4RQe+75R\n-----END CERTIFICATE-----\n"
}

CA Bundle generated: /etc/cfssl/centminmod.com-ca-bundle.pem

cat /etc/cfssl/centminmod.com-ca.pem /etc/cfssl/centminmod.com-ca-intermediate.pem > /etc/cfssl/centminmod.com-ca-bundle.pem
```

# Server Wildcard SSL Certificate

Generate self-signed server wildcard SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication` using `wildcard` option.

* server cert: /etc/cfssl/servercerts/centminmod.com.pem
* server private key: /etc/cfssl/servercerts/centminmod.com-key.pem
* server public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
* server csr: /etc/cfssl/servercerts/centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 wildcard centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/15 04:49:10 [INFO] generate received request
2020/09/15 04:49:10 [INFO] received CSR
2020/09/15 04:49:10 [INFO] generating key: ecdsa-256
2020/09/15 04:49:10 [INFO] encoded CSR
2020/09/15 04:49:10 [INFO] signed certificate with serial number 686335107459070952849333303480510685099787931238

cfssljson -f centminmod.com.json -bare centminmod.com

Extract server certificate public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/servercerts/centminmod.com.pem > /etc/cfssl/servercerts/centminmod.com-publickey.pem
cat /etc/cfssl/servercerts/centminmod.com-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET2WEiAQeC1dsanL90YJ1lNSrlNqa
iRl+UTXul7EqxqY6/uWa5cbMSLEC0fOgcg/7pk5ne+4zbwiUumvrClAwFg==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/servercerts/centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            78:38:54:a3:f9:0d:9b:38:a7:9b:1a:74:05:2a:83:92:ac:d1:ce:66
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:44:00 2020 GMT
            Not After : Sep 13 04:44:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:4f:65:84:88:04:1e:0b:57:6c:6a:72:fd:d1:82:
                    75:94:d4:ab:94:da:9a:89:19:7e:51:35:ee:97:b1:
                    2a:c6:a6:3a:fe:e5:9a:e5:c6:cc:48:b1:02:d1:f3:
                    a0:72:0f:fb:a6:4e:67:7b:ee:33:6f:08:94:ba:6b:
                    eb:0a:50:30:16
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
                03:89:47:A5:01:80:07:A2:63:37:B4:51:A8:4E:4F:95:1F:6A:80:79
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:43:02:20:2c:80:9a:c2:62:49:5d:94:6f:e8:93:d5:ad:6e:
         f2:0a:36:a1:19:9a:4a:6a:a5:6e:21:00:57:64:43:9f:13:a3:
         02:1f:6c:4e:86:fc:54:84:48:ad:fc:71:ef:10:cb:e6:8d:00:
         cf:4f:d3:37:a3:2c:32:9c:0b:65:2c:87:61:3f:9b

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server private key: /etc/cfssl/servercerts/centminmod.com-key.pem
server public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
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
  "serial_number": "686335107459070952849333303480510685099787931238",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-15T04:44:00Z",
  "not_after": "2030-09-13T04:44:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "03:89:47:A5:01:80:07:A2:63:37:B4:51:A8:4E:4F:95:1F:6A:80:79",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICVTCCAf2gAwIBAgIUeDhUo/kNmzinmxp0BSqDkqzRzmYwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDQ0MDBaFw0zMDA5MTMwNDQ0MDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARP\nZYSIBB4LV2xqcv3RgnWU1KuU2pqJGX5RNe6XsSrGpjr+5ZrlxsxIsQLR86ByD/um\nTmd77jNvCJS6a+sKUDAWo4GjMIGgMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQDiUelAYAHomM3tFGo\nTk+VH2qAeTAfBgNVHSMEGDAWgBSBaRVXvWz+5Ig9qon7MIoCUrYw6DArBgNVHREE\nJDAigg5jZW50bWlubW9kLmNvbYIQKi5jZW50bWlubW9kLmNvbTAKBggqhkjOPQQD\nAgNGADBDAiAsgJrCYkldlG/ok9WtbvIKNqEZmkpqpW4hAFdkQ58TowIfbE6G/FSE\nSK38ce8Qy+aNAM9P0zejLDKcC2Ush2E/mw==\n-----END CERTIFICATE-----\n"
}

verify certificate

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/servercerts/centminmod.com.pem
/etc/cfssl/servercerts/centminmod.com.pem: OK
```

# Server SSL Certificate

Generate self-signed server SSL certificate with CA signing for centminmod.com with `TLS Web Server Authentication`

* server cert: /etc/cfssl/servercerts/centminmod.com.pem
* server private key: /etc/cfssl/servercerts/centminmod.com-key.pem
* server public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
* server csr: /etc/cfssl/servercerts/centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/centminmod.com.csr.json

domain with www subdomain inclusion tag `www centminmod.com` on end

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 www centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/15 04:48:40 [INFO] generate received request
2020/09/15 04:48:40 [INFO] received CSR
2020/09/15 04:48:40 [INFO] generating key: ecdsa-256
2020/09/15 04:48:40 [INFO] encoded CSR
2020/09/15 04:48:40 [INFO] signed certificate with serial number 600883771385211323262033291545446809811689207610

cfssljson -f centminmod.com.json -bare centminmod.com

Extract server certificate public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/servercerts/centminmod.com.pem > /etc/cfssl/servercerts/centminmod.com-publickey.pem
cat /etc/cfssl/servercerts/centminmod.com-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJUSa1nXSeOHnPsP9GkFkgnde31fr
oK+8QWtpqqRUQZZwkB6i97PfCxGDiN0FZb9h7OlGVrHBf52ZtTsWRrljxg==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/servercerts/centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            69:40:8f:68:e9:07:42:33:db:e9:0d:47:bc:6c:e6:df:68:a8:f7:3a
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:44:00 2020 GMT
            Not After : Sep 13 04:44:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:25:44:9a:d6:75:d2:78:e1:e7:3e:c3:fd:1a:41:
                    64:82:77:5e:df:57:eb:a0:af:bc:41:6b:69:aa:a4:
                    54:41:96:70:90:1e:a2:f7:b3:df:0b:11:83:88:dd:
                    05:65:bf:61:ec:e9:46:56:b1:c1:7f:9d:99:b5:3b:
                    16:46:b9:63:c6
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
                39:10:D9:08:7E:36:5C:14:F5:1F:39:2A:8E:C1:D9:B2:70:97:F4:88
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:www.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:33:1b:4c:8b:7a:59:67:01:2e:75:2b:36:9b:a9:
         6e:4e:73:88:6c:ad:5a:f0:83:a2:87:e1:28:b4:a1:ad:ac:eb:
         02:20:1c:30:b8:2c:1f:59:ca:59:9b:d1:4f:8f:22:0c:60:2d:
         1b:37:1d:35:29:1f:70:bd:70:79:04:62:d5:e9:d3:e4

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server private key: /etc/cfssl/servercerts/centminmod.com-key.pem
server public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
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
  "serial_number": "600883771385211323262033291545446809811689207610",
  "sans": [
    "centminmod.com",
    "www.centminmod.com"
  ],
  "not_before": "2020-09-15T04:44:00Z",
  "not_after": "2030-09-13T04:44:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "39:10:D9:08:7E:36:5C:14:F5:1F:39:2A:8E:C1:D9:B2:70:97:F4:88",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICWDCCAf+gAwIBAgIUaUCPaOkHQjPb6Q1HvGzm32io9zowCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDQ0MDBaFw0zMDA5MTMwNDQ0MDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQl\nRJrWddJ44ec+w/0aQWSCd17fV+ugr7xBa2mqpFRBlnCQHqL3s98LEYOI3QVlv2Hs\n6UZWscF/nZm1OxZGuWPGo4GlMIGiMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQ5ENkIfjZcFPUfOSqO\nwdmycJf0iDAfBgNVHSMEGDAWgBSBaRVXvWz+5Ig9qon7MIoCUrYw6DAtBgNVHREE\nJjAkgg5jZW50bWlubW9kLmNvbYISd3d3LmNlbnRtaW5tb2QuY29tMAoGCCqGSM49\nBAMCA0cAMEQCIDMbTIt6WWcBLnUrNpupbk5ziGytWvCDoofhKLShrazrAiAcMLgs\nH1nKWZvRT48iDGAtGzcdNSkfcL1weQRi1enT5A==\n-----END CERTIFICATE-----\n"
}

verify certificate

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/servercerts/centminmod.com.pem
/etc/cfssl/servercerts/centminmod.com.pem: OK
```

domain without `www` inclusion

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/15 04:48:08 [INFO] generate received request
2020/09/15 04:48:08 [INFO] received CSR
2020/09/15 04:48:08 [INFO] generating key: ecdsa-256
2020/09/15 04:48:08 [INFO] encoded CSR
2020/09/15 04:48:08 [INFO] signed certificate with serial number 140820043231818578684879409252138385441644214993

cfssljson -f centminmod.com.json -bare centminmod.com

Extract server certificate public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/servercerts/centminmod.com.pem > /etc/cfssl/servercerts/centminmod.com-publickey.pem
cat /etc/cfssl/servercerts/centminmod.com-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdnfzFkpww6jbVdafUN0p9RjNXm1Q
j1bxQhjZDiOOAb1MqnihBxBSuPY2AgXS4mUr6QBqeXtZHqB0rCN/aFFELA==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/servercerts/centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            18:aa:96:d1:40:fe:73:4c:51:e0:96:00:40:74:55:3d:16:59:fa:d1
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:43:00 2020 GMT
            Not After : Sep 13 04:43:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:76:77:f3:16:4a:70:c3:a8:db:55:d6:9f:50:dd:
                    29:f5:18:cd:5e:6d:50:8f:56:f1:42:18:d9:0e:23:
                    8e:01:bd:4c:aa:78:a1:07:10:52:b8:f6:36:02:05:
                    d2:e2:65:2b:e9:00:6a:79:7b:59:1e:a0:74:ac:23:
                    7f:68:51:44:2c
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
                39:A5:43:03:AF:E7:37:8A:2C:FB:99:53:34:7F:23:ED:C5:48:C1:93
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:20:6f:5c:85:08:46:b9:04:b8:fb:81:28:06:3f:10:
         65:99:cb:fe:38:c4:20:d7:be:33:c2:ad:3e:da:a3:75:65:06:
         02:21:00:b8:f9:d5:5e:9a:1a:38:b4:04:1a:93:c7:18:3b:fe:
         4f:8e:82:43:b1:78:ab:c1:23:9a:e2:ad:66:db:06:e6:da

server cert: /etc/cfssl/servercerts/centminmod.com.pem
server private key: /etc/cfssl/servercerts/centminmod.com-key.pem
server public key: /etc/cfssl/servercerts/centminmod.com-publickey.pem
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
  "serial_number": "140820043231818578684879409252138385441644214993",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-15T04:43:00Z",
  "not_after": "2030-09-13T04:43:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "39:A5:43:03:AF:E7:37:8A:2C:FB:99:53:34:7F:23:ED:C5:48:C1:93",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeugAwIBAgIUGKqW0UD+c0xR4JYAQHRVPRZZ+tEwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDQzMDBaFw0zMDA5MTMwNDQzMDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR2\nd/MWSnDDqNtV1p9Q3Sn1GM1ebVCPVvFCGNkOI44BvUyqeKEHEFK49jYCBdLiZSvp\nAGp5e1keoHSsI39oUUQso4GRMIGOMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQ5pUMDr+c3iiz7mVM0\nfyPtxUjBkzAfBgNVHSMEGDAWgBSBaRVXvWz+5Ig9qon7MIoCUrYw6DAZBgNVHREE\nEjAQgg5jZW50bWlubW9kLmNvbTAKBggqhkjOPQQDAgNIADBFAiBvXIUIRrkEuPuB\nKAY/EGWZy/44xCDXvjPCrT7ao3VlBgIhALj51V6aGji0BBqTxxg7/k+OgkOxeKvB\nI5rirWbbBuba\n-----END CERTIFICATE-----\n"
}

verify certificate

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/servercerts/centminmod.com.pem
/etc/cfssl/servercerts/centminmod.com.pem: OK
```

Generate self-signed server SSL certificate with CA signing for server.centminmod.com subdomain with `TLS Web Server Authentication`

* server cert: /etc/cfssl/servercerts/server.centminmod.com.pem
* server private key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
* server public key: /etc/cfssl/servercerts/server.centminmod.com-publickey.pem
* server csr: /etc/cfssl/servercerts/server.centminmod.com.csr
* server csr profile: /etc/cfssl/servercerts/server.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-server centminmod.com 87600 server centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile server -cn server.centminmod.com -hostname server.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem server.centminmod.com.csr.json > server.centminmod.com.json
2020/09/15 04:47:35 [INFO] generate received request
2020/09/15 04:47:35 [INFO] received CSR
2020/09/15 04:47:35 [INFO] generating key: ecdsa-256
2020/09/15 04:47:35 [INFO] encoded CSR
2020/09/15 04:47:35 [INFO] signed certificate with serial number 419336425360932331656433753806248196894946015966

cfssljson -f server.centminmod.com.json -bare server.centminmod.com

Extract server certificate public key: /etc/cfssl/servercerts/server.centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/servercerts/server.centminmod.com.pem > /etc/cfssl/servercerts/server.centminmod.com-publickey.pem
cat /etc/cfssl/servercerts/server.centminmod.com-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkzCCqNjIXot2hdJ1o0NkLRQPFfbx
VUQ68o9nuwyouAe5WaPqBsQvOwz5We1m8vCnCzwQPzZ5uWu63orIcj0Deg==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/servercerts/server.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            49:73:b2:15:c3:b4:44:b3:cf:90:45:1f:fc:94:d3:b0:38:14:ba:de
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:43:00 2020 GMT
            Not After : Sep 13 04:43:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=server.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:93:30:82:a8:d8:c8:5e:8b:76:85:d2:75:a3:43:
                    64:2d:14:0f:15:f6:f1:55:44:3a:f2:8f:67:bb:0c:
                    a8:b8:07:b9:59:a3:ea:06:c4:2f:3b:0c:f9:59:ed:
                    66:f2:f0:a7:0b:3c:10:3f:36:79:b9:6b:ba:de:8a:
                    c8:72:3d:03:7a
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
                4F:50:0B:DB:AC:B4:E6:60:AA:95:4B:9D:50:DB:61:15:AF:31:B8:B0
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:server.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:b0:94:9e:7b:03:bb:18:a7:f8:d6:40:4c:9d:
         46:c2:55:8d:51:12:d3:f5:37:9f:9d:62:76:9e:49:34:56:5b:
         6d:02:21:00:e0:3c:0d:40:e0:05:1b:53:34:f4:30:5e:17:7e:
         92:2b:b2:b7:f2:31:65:1b:8f:38:33:97:0f:a1:5e:cd:18:ba

server cert: /etc/cfssl/servercerts/server.centminmod.com.pem
server private key: /etc/cfssl/servercerts/server.centminmod.com-key.pem
server public key: /etc/cfssl/servercerts/server.centminmod.com-publickey.pem
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
  "serial_number": "419336425360932331656433753806248196894946015966",
  "sans": [
    "server.centminmod.com"
  ],
  "not_before": "2020-09-15T04:43:00Z",
  "not_after": "2030-09-13T04:43:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "4F:50:0B:DB:AC:B4:E6:60:AA:95:4B:9D:50:DB:61:15:AF:31:B8:B0",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICVDCCAfmgAwIBAgIUSXOyFcO0RLPPkEUf/JTTsDgUut4wCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDQzMDBaFw0zMDA5MTMwNDQzMDBaMFIxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEeMBwG\nA1UEAxMVc2VydmVyLmNlbnRtaW5tb2QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAEkzCCqNjIXot2hdJ1o0NkLRQPFfbxVUQ68o9nuwyouAe5WaPqBsQvOwz5\nWe1m8vCnCzwQPzZ5uWu63orIcj0DeqOBmDCBlTAOBgNVHQ8BAf8EBAMCBaAwEwYD\nVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUT1AL26y0\n5mCqlUudUNthFa8xuLAwHwYDVR0jBBgwFoAUgWkVV71s/uSIPaqJ+zCKAlK2MOgw\nIAYDVR0RBBkwF4IVc2VydmVyLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0kA\nMEYCIQCwlJ57A7sYp/jWQEydRsJVjVES0/U3n51idp5JNFZbbQIhAOA8DUDgBRtT\nNPQwXhd+kiuyt/IxZRuPODOXD6FezRi6\n-----END CERTIFICATE-----\n"
}

verify certificate

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/servercerts/server.centminmod.com.pem
/etc/cfssl/servercerts/server.centminmod.com.pem: OK
```

# Client SSL Certificate

Generate self-signed client SSL certificate with CA signing for centminmod.com with `TLS Web Client Authentication`

* client pkcs12: /etc/cfssl/clientcerts/centminmod.com.p12
* client cert: /etc/cfssl/clientcerts/centminmod.com.pem
* client private key: /etc/cfssl/clientcerts/centminmod.com-key.pem
* client public key: /etc/cfssl/clientcerts/centminmod.com-publickey.pem
* client csr: /etc/cfssl/clientcerts/centminmod.com.csr
* client csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json

Included in output are Cloudflare API instructions for uploading the generated client SSL certificate to Cloudflare for use on a custom hostname configured Cloudflare Authenticated Origin Pull certificate as outlined at [https://developers.cloudflare.com/ssl/origin/authenticated-origin-pull/#per-hostname-authenticated-origin-pull-using-customer-certificates-per-hostname](https://developers.cloudflare.com/ssl/origin/authenticated-origin-pull/#per-hostname-authenticated-origin-pull-using-customer-certificates-per-hostname).

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn centminmod.com -hostname centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/15 04:46:56 [INFO] generate received request
2020/09/15 04:46:56 [INFO] received CSR
2020/09/15 04:46:56 [INFO] generating key: ecdsa-256
2020/09/15 04:46:56 [INFO] encoded CSR
2020/09/15 04:46:56 [INFO] signed certificate with serial number 239526218581753485010645879334122855210982084209

cfssljson -f centminmod.com.json -bare centminmod.com

Extract client certificate public key: /etc/cfssl/clientcerts/centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/clientcerts/centminmod.com.pem > /etc/cfssl/clientcerts/centminmod.com-publickey.pem
cat /etc/cfssl/clientcerts/centminmod.com-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoSEh3BmIOxMVnoT9WY8EJAte19JW
aPq9gbdPQ5wwGWduY8BeujksIUAnuqe2ArA4iZuV9ctGlkWOB0zyMHAnDQ==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/clientcerts/centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            29:f4:ba:24:0a:ac:23:8a:f4:1e:d2:8e:bc:c2:db:92:9a:3c:8e:71
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:42:00 2020 GMT
            Not After : Sep 13 04:42:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:a1:21:21:dc:19:88:3b:13:15:9e:84:fd:59:8f:
                    04:24:0b:5e:d7:d2:56:68:fa:bd:81:b7:4f:43:9c:
                    30:19:67:6e:63:c0:5e:ba:39:2c:21:40:27:ba:a7:
                    b6:02:b0:38:89:9b:95:f5:cb:46:96:45:8e:07:4c:
                    f2:30:70:27:0d
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
                6E:52:E8:0C:A9:F5:D9:25:30:61:D4:77:87:DB:FB:AA:47:54:E9:7C
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:92:52:8c:8c:41:9f:fe:b5:d1:a7:14:39:e1:
         52:a0:63:b7:02:23:63:e8:2f:ce:e0:7a:0c:c0:19:63:89:9c:
         bb:02:21:00:c5:e7:89:e6:9e:4d:f3:3c:a8:08:8d:2e:8d:43:
         6c:18:38:99:a1:08:c8:27:1e:6c:5c:a9:7e:bf:64:1e:34:45

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/clientcerts/centminmod.com.p12 -inkey /etc/cfssl/clientcerts/centminmod.com-key.pem -in /etc/cfssl/clientcerts/centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

client pkcs12: /etc/cfssl/clientcerts/centminmod.com.p12
client cert: /etc/cfssl/clientcerts/centminmod.com.pem
client private key: /etc/cfssl/clientcerts/centminmod.com-key.pem
client public key: /etc/cfssl/clientcerts/centminmod.com-publickey.pem
client csr: /etc/cfssl/clientcerts/centminmod.com.csr
client csr profile: /etc/cfssl/clientcerts/centminmod.com.csr.json

Generate /etc/cfssl/clientcerts/centminmod.com-client-bundle.pem
cat /etc/cfssl/clientcerts/centminmod.com.pem /etc/cfssl/centminmod.com-ca-bundle.pem > /etc/cfssl/clientcerts/centminmod.com-client-bundle.pem
client bundle chain: /etc/cfssl/clientcerts/centminmod.com-client-bundle.pem


Check certificate purpose:
openssl x509 -in /etc/cfssl/clientcerts/centminmod.com.pem -noout -purpose
Certificate purposes:
SSL client : Yes
SSL client CA : No
SSL server : No
SSL server CA : No
Netscape SSL server : No
Netscape SSL server CA : No
S/MIME signing : No
S/MIME signing CA : No
S/MIME encryption : No
S/MIME encryption CA : No
CRL signing : No
CRL signing CA : No
Any Purpose : Yes
Any Purpose CA : Yes
OCSP helper : Yes
OCSP helper CA : No
Time Stamp signing : No
Time Stamp signing CA : No

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
  "serial_number": "239526218581753485010645879334122855210982084209",
  "sans": [
    "centminmod.com"
  ],
  "not_before": "2020-09-15T04:42:00Z",
  "not_after": "2030-09-13T04:42:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "6E:52:E8:0C:A9:F5:D9:25:30:61:D4:77:87:DB:FB:AA:47:54:E9:7C",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICRjCCAeugAwIBAgIUKfS6JAqsI4r0HtKOvMLbkpo8jnEwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDQyMDBaFw0zMDA5MTMwNDQyMDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASh\nISHcGYg7ExWehP1ZjwQkC17X0lZo+r2Bt09DnDAZZ25jwF66OSwhQCe6p7YCsDiJ\nm5X1y0aWRY4HTPIwcCcNo4GRMIGOMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\nBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRuUugMqfXZJTBh1HeH\n2/uqR1TpfDAfBgNVHSMEGDAWgBSBaRVXvWz+5Ig9qon7MIoCUrYw6DAZBgNVHREE\nEjAQgg5jZW50bWlubW9kLmNvbTAKBggqhkjOPQQDAgNJADBGAiEAklKMjEGf/rXR\npxQ54VKgY7cCI2PoL87gegzAGWOJnLsCIQDF54nmnk3zPKgIjS6NQ2wYOJmhCMgn\nHmxcqX6/ZB40RQ==\n-----END CERTIFICATE-----\n"
}

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/clientcerts/centminmod.com.pem
/etc/cfssl/clientcerts/centminmod.com.pem: OK

---------------------------------------------------------------------------
For Cloudflare Enterprise custom Authenticated Origin Pull Client Certificate API Upload
---------------------------------------------------------------------------
- https://developers.cloudflare.com/ssl/origin/authenticated-origin-pull/#per-hostname-authenticated-origin-pull-using-customer-certificates-per-hostname
- https://api.cloudflare.com/#per-hostname-authenticated-origin-pull-upload-a-hostname-client-certificate

populate variables

MYCERT=$(cat /etc/cfssl/clientcerts/centminmod.com.pem |perl -pe 's/\r?\n/\\n/'|sed -e 's/..$//')
MYKEY=$(cat /etc/cfssl/clientcerts/centminmod.com-key.pem | perl -pe 's/\r?\n/\\n/'|sed -e's/..$//')
request_body="{ \"certificate\": \"$MYCERT\", \"private_key\": \"$MYKEY\" }" 

export cfzoneid=cf_zone_id
export cfemail=cf_account_email
export cftoken=cf_account_global_api_keytoken
export cf_hostname=domain_name_on_ssl_certificate

---------------------------------------------------------------------------
Upload TLS client certificate via CF API
---------------------------------------------------------------------------

curl -sX POST https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/certificates -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d "$request_body" | jq | tee /etc/cfssl/clientcerts/centminmod.com-cf-origin-tls-cleint-auth-cert-upload.txt

export clientcert_id=$(jq -r '.result.id' /etc/cfssl/clientcerts/centminmod.com-cf-origin-tls-cleint-auth-cert-upload.txt)
echo "$clientcert_id" > /etc/cfssl/clientcerts/centminmod.com-cf-origin-tls-cleint-auth-cert-upload-clientcert-id.txt

---------------------------------------------------------------------------
Check uploaded TLS client certificate via CF API
---------------------------------------------------------------------------

curl -sX GET "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/certificates/$clientcert_id" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d "$request_body" | jq | tee /etc/cfssl/clientcerts/centminmod.com-cf-origin-tls-cleint-auth-cert-upload-status.txt

---------------------------------------------------------------------------
To delete uploaded TLS client certificate via CF API
---------------------------------------------------------------------------

curl -sX DELETE "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/certificates/$clientcert_id" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d "$request_body" | jq | tee /etc/cfssl/clientcerts/centminmod.com-cf-origin-tls-cleint-auth-cert-upload-delete.txt

---------------------------------------------------------------------------
Enable specific hostname Authenticated Origin Pull via Cloudflare API
---------------------------------------------------------------------------

curl -sX PUT https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d $(jq -c -n --arg cf_hostname $cf_hostname --arg clientcert_id $clientcert_id $(echo "{\"config\":[{\"hostname\":\"$cf_hostname\",\"cert_id\":\"$clientcert_id\",\"enabled\":true}]}")) | jq 

---------------------------------------------------------------------------
Disable specific hostname Authenticated Origin Pull via Cloudflare API
---------------------------------------------------------------------------

curl -sX PUT https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d $(jq -c -n --arg cf_hostname $cf_hostname --arg clientcert_id $clientcert_id $(echo "{\"config\":[{\"hostname\":\"$cf_hostname\",\"cert_id\":\"$clientcert_id\",\"enabled\":false}]}")) | jq

---------------------------------------------------------------------------
Check CF Status for specific hostname Authenticated Origin Pull via Cloudflare API
---------------------------------------------------------------------------

curl -sX GET "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/$cf_hostname" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" | jq

---------------------------------------------------------------------------
List uploaded Origin TLS Client Authenticatied Certificates
---------------------------------------------------------------------------

curl -sX GET "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" | jq
```

Generate self-signed client SSL certificate with CA signing for client.centminmod.com subdomain with `TLS Web Client Authentication`

* client pkcs12: /etc/cfssl/clientcerts/client.centminmod.com.p12
* client cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
* client private key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
* client public key: /etc/cfssl/clientcerts/client.centminmod.com-publickey.pem
* client csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
* client csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json

Included in output are Cloudflare API instructions for uploading the generated client SSL certificate to Cloudflare for use on a custom hostname configured Cloudflare Authenticated Origin Pull certificate as outlined at [https://developers.cloudflare.com/ssl/origin/authenticated-origin-pull/#per-hostname-authenticated-origin-pull-using-customer-certificates-per-hostname](https://developers.cloudflare.com/ssl/origin/authenticated-origin-pull/#per-hostname-authenticated-origin-pull-using-customer-certificates-per-hostname).

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-client centminmod.com 87600 client centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile client -cn client.centminmod.com -hostname client.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem client.centminmod.com.csr.json > client.centminmod.com.json
2020/09/15 04:46:12 [INFO] generate received request
2020/09/15 04:46:12 [INFO] received CSR
2020/09/15 04:46:12 [INFO] generating key: ecdsa-256
2020/09/15 04:46:12 [INFO] encoded CSR
2020/09/15 04:46:12 [INFO] signed certificate with serial number 330776793857179573011736319641964465614109840512

cfssljson -f client.centminmod.com.json -bare client.centminmod.com

Extract client certificate public key: /etc/cfssl/clientcerts/client.centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/clientcerts/client.centminmod.com.pem > /etc/cfssl/clientcerts/client.centminmod.com-publickey.pem
cat /etc/cfssl/clientcerts/client.centminmod.com-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZcH4s8d49ToL5xZzbsXLz706ziqs
AKMCTkXgcvm0dJcNqhKv9HzuJDviDxnsz9eV1dSd+pF9WtnVZTfHQh6hVQ==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/clientcerts/client.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            39:f0:8b:5f:67:d2:9a:71:cb:b2:03:48:c6:f7:23:f0:59:dc:94:80
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:41:00 2020 GMT
            Not After : Sep 13 04:41:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=client.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:65:c1:f8:b3:c7:78:f5:3a:0b:e7:16:73:6e:c5:
                    cb:cf:bd:3a:ce:2a:ac:00:a3:02:4e:45:e0:72:f9:
                    b4:74:97:0d:aa:12:af:f4:7c:ee:24:3b:e2:0f:19:
                    ec:cf:d7:95:d5:d4:9d:fa:91:7d:5a:d9:d5:65:37:
                    c7:42:1e:a1:55
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
                9C:8E:FB:6F:90:6D:B7:E4:D7:1C:59:DC:DF:BF:EC:69:9E:34:D6:7D
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:client.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:46:02:21:00:e7:c1:d9:1f:8a:52:92:7e:23:29:33:a5:63:
         fa:88:a5:2b:f2:73:5b:4d:e3:a0:2e:09:4b:6e:19:f3:a0:92:
         be:02:21:00:a9:d9:8e:17:ba:94:4c:52:44:b2:2a:11:0f:1f:
         12:fc:68:ad:ef:dc:39:f5:b2:c5:b8:08:d8:24:3f:b7:64:57

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/clientcerts/client.centminmod.com.p12 -inkey /etc/cfssl/clientcerts/client.centminmod.com-key.pem -in /etc/cfssl/clientcerts/client.centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

client pkcs12: /etc/cfssl/clientcerts/client.centminmod.com.p12
client cert: /etc/cfssl/clientcerts/client.centminmod.com.pem
client private key: /etc/cfssl/clientcerts/client.centminmod.com-key.pem
client public key: /etc/cfssl/clientcerts/client.centminmod.com-publickey.pem
client csr: /etc/cfssl/clientcerts/client.centminmod.com.csr
client csr profile: /etc/cfssl/clientcerts/client.centminmod.com.csr.json

Generate /etc/cfssl/clientcerts/client.centminmod.com-client-bundle.pem
cat /etc/cfssl/clientcerts/client.centminmod.com.pem /etc/cfssl/centminmod.com-ca-bundle.pem > /etc/cfssl/clientcerts/client.centminmod.com-client-bundle.pem
client bundle chain: /etc/cfssl/clientcerts/client.centminmod.com-client-bundle.pem


Check certificate purpose:
openssl x509 -in /etc/cfssl/clientcerts/client.centminmod.com.pem -noout -purpose
Certificate purposes:
SSL client : Yes
SSL client CA : No
SSL server : No
SSL server CA : No
Netscape SSL server : No
Netscape SSL server CA : No
S/MIME signing : No
S/MIME signing CA : No
S/MIME encryption : No
S/MIME encryption CA : No
CRL signing : No
CRL signing CA : No
Any Purpose : Yes
Any Purpose CA : Yes
OCSP helper : Yes
OCSP helper CA : No
Time Stamp signing : No
Time Stamp signing CA : No

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
  "serial_number": "330776793857179573011736319641964465614109840512",
  "sans": [
    "client.centminmod.com"
  ],
  "not_before": "2020-09-15T04:41:00Z",
  "not_after": "2030-09-13T04:41:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "9C:8E:FB:6F:90:6D:B7:E4:D7:1C:59:DC:DF:BF:EC:69:9E:34:D6:7D",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICVDCCAfmgAwIBAgIUOfCLX2fSmnHLsgNIxvcj8FnclIAwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDQxMDBaFw0zMDA5MTMwNDQxMDBaMFIxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEeMBwG\nA1UEAxMVY2xpZW50LmNlbnRtaW5tb2QuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAEZcH4s8d49ToL5xZzbsXLz706ziqsAKMCTkXgcvm0dJcNqhKv9HzuJDvi\nDxnsz9eV1dSd+pF9WtnVZTfHQh6hVaOBmDCBlTAOBgNVHQ8BAf8EBAMCBaAwEwYD\nVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUnI77b5Bt\nt+TXHFnc37/saZ401n0wHwYDVR0jBBgwFoAUgWkVV71s/uSIPaqJ+zCKAlK2MOgw\nIAYDVR0RBBkwF4IVY2xpZW50LmNlbnRtaW5tb2QuY29tMAoGCCqGSM49BAMCA0kA\nMEYCIQDnwdkfilKSfiMpM6Vj+oilK/JzW03joC4JS24Z86CSvgIhAKnZjhe6lExS\nRLIqEQ8fEvxore/cOfWyxbgI2CQ/t2RX\n-----END CERTIFICATE-----\n"
}

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/clientcerts/client.centminmod.com.pem
/etc/cfssl/clientcerts/client.centminmod.com.pem: OK

---------------------------------------------------------------------------
For Cloudflare Enterprise custom Authenticated Origin Pull Client Certificate API Upload
---------------------------------------------------------------------------
- https://developers.cloudflare.com/ssl/origin/authenticated-origin-pull/#per-hostname-authenticated-origin-pull-using-customer-certificates-per-hostname
- https://api.cloudflare.com/#per-hostname-authenticated-origin-pull-upload-a-hostname-client-certificate

populate variables

MYCERT=$(cat /etc/cfssl/clientcerts/client.centminmod.com.pem |perl -pe 's/\r?\n/\\n/'|sed -e 's/..$//')
MYKEY=$(cat /etc/cfssl/clientcerts/client.centminmod.com-key.pem | perl -pe 's/\r?\n/\\n/'|sed -e's/..$//')
request_body="{ \"certificate\": \"$MYCERT\", \"private_key\": \"$MYKEY\" }" 

export cfzoneid=cf_zone_id
export cfemail=cf_account_email
export cftoken=cf_account_global_api_keytoken
export cf_hostname=domain_name_on_ssl_certificate

---------------------------------------------------------------------------
Upload TLS client certificate via CF API
---------------------------------------------------------------------------

curl -sX POST https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/certificates -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d "$request_body" | jq | tee /etc/cfssl/clientcerts/client.centminmod.com-cf-origin-tls-cleint-auth-cert-upload.txt

export clientcert_id=$(jq -r '.result.id' /etc/cfssl/clientcerts/client.centminmod.com-cf-origin-tls-cleint-auth-cert-upload.txt)
echo "$clientcert_id" > /etc/cfssl/clientcerts/client.centminmod.com-cf-origin-tls-cleint-auth-cert-upload-clientcert-id.txt

---------------------------------------------------------------------------
Check uploaded TLS client certificate via CF API
---------------------------------------------------------------------------

curl -sX GET "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/certificates/$clientcert_id" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d "$request_body" | jq | tee /etc/cfssl/clientcerts/client.centminmod.com-cf-origin-tls-cleint-auth-cert-upload-status.txt

---------------------------------------------------------------------------
To delete uploaded TLS client certificate via CF API
---------------------------------------------------------------------------

curl -sX DELETE "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/certificates/$clientcert_id" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d "$request_body" | jq | tee /etc/cfssl/clientcerts/client.centminmod.com-cf-origin-tls-cleint-auth-cert-upload-delete.txt

---------------------------------------------------------------------------
Enable specific hostname Authenticated Origin Pull via Cloudflare API
---------------------------------------------------------------------------

curl -sX PUT https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d $(jq -c -n --arg cf_hostname $cf_hostname --arg clientcert_id $clientcert_id $(echo "{\"config\":[{\"hostname\":\"$cf_hostname\",\"cert_id\":\"$clientcert_id\",\"enabled\":true}]}")) | jq 

---------------------------------------------------------------------------
Disable specific hostname Authenticated Origin Pull via Cloudflare API
---------------------------------------------------------------------------

curl -sX PUT https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" -d $(jq -c -n --arg cf_hostname $cf_hostname --arg clientcert_id $clientcert_id $(echo "{\"config\":[{\"hostname\":\"$cf_hostname\",\"cert_id\":\"$clientcert_id\",\"enabled\":false}]}")) | jq

---------------------------------------------------------------------------
Check CF Status for specific hostname Authenticated Origin Pull via Cloudflare API
---------------------------------------------------------------------------

curl -sX GET "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth/hostnames/$cf_hostname" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" | jq

---------------------------------------------------------------------------
List uploaded Origin TLS Client Authenticatied Certificates
---------------------------------------------------------------------------

curl -sX GET "https://api.cloudflare.com/client/v4/zones/$cfzoneid/origin_tls_client_auth" -H "X-Auth-Email: $cfemail" -H "X-Auth-Key: $cftoken" -H "Content-Type: application/json" | jq
```

# Peer Wildcard SSL Certificate

Generate self-signed peer wildcard SSL certificate with CA signing for centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

* peer pkcs12: /etc/cfssl/peercerts/centminmod.com.p12
* peer cert: /etc/cfssl/peercerts/centminmod.com.pem
* peer private key: /etc/cfssl/peercerts/centminmod.com-key.pem
* peer public key: /etc/cfssl/peercerts/centminmod.com-publickey.pem
* peer csr: /etc/cfssl/peercerts/centminmod.com.csr
* peer csr profile: /etc/cfssl/peercerts/centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 wildcard centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile peer -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.com-ca-intermediate-key.pem centminmod.com.csr.json > centminmod.com.json
2020/09/15 04:45:23 [INFO] generate received request
2020/09/15 04:45:23 [INFO] received CSR
2020/09/15 04:45:23 [INFO] generating key: ecdsa-256
2020/09/15 04:45:23 [INFO] encoded CSR
2020/09/15 04:45:23 [INFO] signed certificate with serial number 364491867088419011259470270742378449429086468712

cfssljson -f centminmod.com.json -bare centminmod.com

Extract peer certificate public key: /etc/cfssl/peercerts/centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/peercerts/centminmod.com.pem > /etc/cfssl/peercerts/centminmod.com-publickey.pem
cat /etc/cfssl/peercerts/centminmod.com-publickey.pem

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn2QjEndBmki89RnI6pqPG1OR7iPr
3TB4Td/5J8vwuFD1jxjG2yN8S1KGpMRXdvM0O8P25RuHqOCHErbsSEOorA==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/peercerts/centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3f:d8:61:6e:b5:2f:db:dd:82:e2:68:9d:70:b9:fa:7b:30:bd:fa:68
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:40:00 2020 GMT
            Not After : Sep 13 04:40:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:9f:64:23:12:77:41:9a:48:bc:f5:19:c8:ea:9a:
                    8f:1b:53:91:ee:23:eb:dd:30:78:4d:df:f9:27:cb:
                    f0:b8:50:f5:8f:18:c6:db:23:7c:4b:52:86:a4:c4:
                    57:76:f3:34:3b:c3:f6:e5:1b:87:a8:e0:87:12:b6:
                    ec:48:43:a8:ac
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
                58:41:18:19:32:49:F2:16:CB:43:B2:77:2D:39:9B:35:FD:CD:BB:9D
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:centminmod.com, DNS:*.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:b3:ce:32:fa:99:30:09:4c:ce:b1:0e:ad:4c:
         37:a7:40:7d:88:06:0c:9e:9d:8e:5b:b5:e5:69:1c:21:82:cb:
         12:02:20:4f:69:a8:2a:1c:43:4b:22:92:58:03:62:ca:23:75:
         43:0f:de:3e:59:72:8d:a4:55:aa:e4:df:ac:50:16:73:41

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/peercerts/centminmod.com.p12 -inkey /etc/cfssl/peercerts/centminmod.com-key.pem -in /etc/cfssl/peercerts/centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

peer pkcs12: /etc/cfssl/peercerts/centminmod.com.p12
peer cert: /etc/cfssl/peercerts/centminmod.com.pem
peer private key: /etc/cfssl/peercerts/centminmod.com-key.pem
peer public key: /etc/cfssl/peercerts/centminmod.com-publickey.pem
peer csr: /etc/cfssl/peercerts/centminmod.com.csr
peer csr profile: /etc/cfssl/peercerts/centminmod.com.csr.json

Generate /etc/cfssl/peercerts/centminmod.com-peer-bundle.pem
cat /etc/cfssl/peercerts/centminmod.com.pem /etc/cfssl/centminmod.com-ca-bundle.pem > /etc/cfssl/peercerts/centminmod.com-peer-bundle.pem
peer bundle chain: /etc/cfssl/clientcerts/centminmod.com-client-bundle.pem


Check certificate purpose:
openssl x509 -in /etc/cfssl/peercerts/centminmod.com.pem -noout -purpose
Certificate purposes:
SSL client : Yes
SSL client CA : No
SSL server : Yes
SSL server CA : No
Netscape SSL server : Yes
Netscape SSL server CA : No
S/MIME signing : No
S/MIME signing CA : No
S/MIME encryption : No
S/MIME encryption CA : No
CRL signing : No
CRL signing CA : No
Any Purpose : Yes
Any Purpose CA : Yes
OCSP helper : Yes
OCSP helper CA : No
Time Stamp signing : No
Time Stamp signing CA : No

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
  "serial_number": "364491867088419011259470270742378449429086468712",
  "sans": [
    "centminmod.com",
    "*.centminmod.com"
  ],
  "not_before": "2020-09-15T04:40:00Z",
  "not_after": "2030-09-13T04:40:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "58:41:18:19:32:49:F2:16:CB:43:B2:77:2D:39:9B:35:FD:CD:BB:9D",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICYTCCAgegAwIBAgIUP9hhbrUv292C4midcLn6ezC9+mgwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDQwMDBaFw0zMDA5MTMwNDQwMDBaMEsxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEXMBUG\nA1UEAxMOY2VudG1pbm1vZC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASf\nZCMSd0GaSLz1Gcjqmo8bU5HuI+vdMHhN3/kny/C4UPWPGMbbI3xLUoakxFd28zQ7\nw/blG4eo4IcStuxIQ6iso4GtMIGqMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAU\nBggrBgEFBQcDAgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUWEEY\nGTJJ8hbLQ7J3LTmbNf3Nu50wHwYDVR0jBBgwFoAUgWkVV71s/uSIPaqJ+zCKAlK2\nMOgwKwYDVR0RBCQwIoIOY2VudG1pbm1vZC5jb22CECouY2VudG1pbm1vZC5jb20w\nCgYIKoZIzj0EAwIDSAAwRQIhALPOMvqZMAlMzrEOrUw3p0B9iAYMnp2OW7XlaRwh\ngssSAiBPaagqHENLIpJYA2LKI3VDD94+WXKNpFWq5N+sUBZzQQ==\n-----END CERTIFICATE-----\n"
}

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/peercerts/centminmod.com.pem
/etc/cfssl/peercerts/centminmod.com.pem: OK
```

# Peer SSL Certificate

Generate self-signed peer SSL certificate with CA signing for peer.centminmod.com subdomain with `TLS Web Client Authentication` and `TLS Web Server Authentication` 

* peer pkcs12: /etc/cfssl/peercerts/peer.centminmod.com.p12
* peer cert: /etc/cfssl/peercerts/peer.centminmod.com.pem
* peer private key: /etc/cfssl/peercerts/peer.centminmod.com-key.pem
* peer public key: /etc/cfssl/peercerts/peer.centminmod.com-publickey.pem
* peer csr: /etc/cfssl/peercerts/peer.centminmod.com.csr
* peer csr profile: /etc/cfssl/peercerts/peer.centminmod.com.csr.json

```
/root/tools/cfssl-ca-ssl/cfssl-ca-ssl.sh gen-peer centminmod.com 87600 peer centminmod.com

cfssl gencert -config /etc/cfssl/profile.json -profile peer -cn peer.centminmod.com -hostname peer.centminmod.com -ca /etc/cfssl/centminmod.com-ca-intermediate.pem -ca-key /etc/cfssl/centminmod.comca-intermediate-key.pem peer.centminmod.com.csr.json > peer.centminmod.com.json
2020/09/15 04:43:49 [INFO] generate received request
2020/09/15 04:43:49 [INFO] received CSR
2020/09/15 04:43:49 [INFO] generating key: ecdsa-256
2020/09/15 04:43:49 [INFO] encoded CSR
2020/09/15 04:43:49 [INFO] signed certificate with serial number 726785261521537832380994474660947973220290265417

cfssljson -f peer.centminmod.com.json -bare peer.centminmod.com

Extract peer certificate public key: /etc/cfssl/peercerts/peer.centminmod.com-publickey.pem
openssl x509 -pubkey -noout -in /etc/cfssl/peercerts/peer.centminmod.com.pem > /etc/cfssl/peercerts/peer.centminmod.com-publickey.pem
cat /etc/cfssl/peercerts/peer.centminmod.com-publickey.pem
echo "$clientcert_id" > /etc/cfssl/clientcerts/client.centminmod.com-cf-origin-tls-cleint-auth-cert-upload-clientcert-id.txt

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw4/9CH6YdBUa6/YgsvkRAXEhezMN
M83EMPgyyZY2RgtWa2hGjfQgZy4f8pyyaxz42SdhEo99dufaIXlnR6rpjg==
-----END PUBLIC KEY-----


openssl x509 -in /etc/cfssl/peercerts/peer.centminmod.com.pem -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7f:4e:2d:a2:f2:db:cd:63:d4:41:30:70:d2:8b:b2:96:50:0c:01:49
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=US, ST=CA, L=San Francisco, OU=Intermediate CA, CN=Intermediate CA
        Validity
            Not Before: Sep 15 04:39:00 2020 GMT
            Not After : Sep 13 04:39:00 2030 GMT
        Subject: C=US, ST=CA, L=San Francisco, CN=peer.centminmod.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:c3:8f:fd:08:7e:98:74:15:1a:eb:f6:20:b2:f9:
                    11:01:71:21:7b:33:0d:33:cd:c4:30:f8:32:c9:96:
                    36:46:0b:56:6b:68:46:8d:f4:20:67:2e:1f:f2:9c:
                    b2:6b:1c:f8:d9:27:61:12:8f:7d:76:e7:da:21:79:
                    67:47:aa:e9:8e
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
                30:91:E8:CF:20:01:A5:F9:B8:84:CD:A4:D3:51:45:F1:F8:BA:61:C1
            X509v3 Authority Key Identifier: 
                keyid:81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8

            X509v3 Subject Alternative Name: 
                DNS:peer.centminmod.com
    Signature Algorithm: ecdsa-with-SHA256
         30:45:02:21:00:b9:a6:b2:a9:77:f1:6c:7f:c2:ec:f0:d4:63:
         a4:a0:db:15:ef:9e:ce:9d:aa:c1:46:d5:52:03:99:12:b8:e3:
         d5:02:20:65:08:57:09:14:28:65:03:93:a7:dd:3c:35:fd:33:
         8c:77:d7:08:b8:70:1c:ab:17:0e:18:88:50:15:f2:1e:31

Generate pkcs12 format
openssl pkcs12 -export -out /etc/cfssl/peercerts/peer.centminmod.com.p12 -inkey /etc/cfssl/peercerts/peer.centminmod.com-key.pem -in /etc/cfssl/peercerts/peer.centminmod.com.pem -certfile /etc/cfssl/centminmod.com-ca-bundle.pem -passin pass: -passout pass:

peer pkcs12: /etc/cfssl/peercerts/peer.centminmod.com.p12
peer cert: /etc/cfssl/peercerts/peer.centminmod.com.pem
peer private key: /etc/cfssl/peercerts/peer.centminmod.com-key.pem
peer public key: /etc/cfssl/peercerts/peer.centminmod.com-publickey.pem
peer csr: /etc/cfssl/peercerts/peer.centminmod.com.csr
peer csr profile: /etc/cfssl/peercerts/peer.centminmod.com.csr.json

Generate /etc/cfssl/peercerts/peer.centminmod.com-peer-bundle.pem
cat /etc/cfssl/peercerts/peer.centminmod.com.pem /etc/cfssl/centminmod.com-ca-bundle.pem > /etc/cfssl/peercerts/peer.centminmod.com-peer-bundle.pem
peer bundle chain: /etc/cfssl/clientcerts/peer.centminmod.com-client-bundle.pem


Check certificate purpose:
openssl x509 -in /etc/cfssl/peercerts/peer.centminmod.com.pem -noout -purpose
Certificate purposes:
SSL client : Yes
SSL client CA : No
SSL server : Yes
SSL server CA : No
Netscape SSL server : Yes
Netscape SSL server CA : No
S/MIME signing : No
S/MIME signing CA : No
S/MIME encryption : No
S/MIME encryption CA : No
CRL signing : No
CRL signing CA : No
Any Purpose : Yes
Any Purpose CA : Yes
OCSP helper : Yes
OCSP helper CA : No
Time Stamp signing : No
Time Stamp signing CA : No

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
  "serial_number": "726785261521537832380994474660947973220290265417",
  "sans": [
    "peer.centminmod.com"
  ],
  "not_before": "2020-09-15T04:39:00Z",
  "not_after": "2030-09-13T04:39:00Z",
  "sigalg": "ECDSAWithSHA256",
  "authority_key_id": "81:69:15:57:BD:6C:FE:E4:88:3D:AA:89:FB:30:8A:02:52:B6:30:E8",
  "subject_key_id": "30:91:E8:CF:20:01:A5:F9:B8:84:CD:A4:D3:51:45:F1:F8:BA:61:C1",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICWTCCAf+gAwIBAgIUf04tovLbzWPUQTBw0ouyllAMAUkwCgYIKoZIzj0EAwIw\nZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRgwFgYDVQQLEw9JbnRlcm1lZGlhdGUgQ0ExGDAWBgNVBAMTD0ludGVybWVk\naWF0ZSBDQTAeFw0yMDA5MTUwNDM5MDBaFw0zMDA5MTMwNDM5MDBaMFAxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEcMBoG\nA1UEAxMTcGVlci5jZW50bWlubW9kLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABMOP/Qh+mHQVGuv2ILL5EQFxIXszDTPNxDD4MsmWNkYLVmtoRo30IGcuH/Kc\nsmsc+NknYRKPfXbn2iF5Z0eq6Y6jgaAwgZ0wDgYDVR0PAQH/BAQDAgWgMB0GA1Ud\nJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW\nBBQwkejPIAGl+biEzaTTUUXx+LphwTAfBgNVHSMEGDAWgBSBaRVXvWz+5Ig9qon7\nMIoCUrYw6DAeBgNVHREEFzAVghNwZWVyLmNlbnRtaW5tb2QuY29tMAoGCCqGSM49\nBAMCA0gAMEUCIQC5prKpd/Fsf8Ls8NRjpKDbFe+ezp2qwUbVUgOZErjj1QIgZQhX\nCRQoZQOTp908Nf0zjHfXCLhwHKsXDhiIUBXyHjE=\n-----END CERTIFICATE-----\n"
}

openssl verify -CAfile /etc/cfssl/centminmod.com-ca-bundle.pem /etc/cfssl/peercerts/peer.centminmod.com.pem
/etc/cfssl/peercerts/peer.centminmod.com.pem: OK
```

# Nginx Configuration

```
mkdir -p /usr/local/nginx/conf/ssl/cacerts_certificates
cp -a /etc/cfssl/centminmod.com-ca-bundle.pem /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem
```

```
ssl_client_certificate /usr/local/nginx/conf/ssl/cacerts_certificates/centminmod.com-ca-bundle.pem;
ssl_verify_client on;
ssl_verify_depth 1;

if ($ssl_client_verify != SUCCESS) {
    return 403;
}

# optional diagnostic headers
  add_header SSL-Client-Verify $ssl_client_verify;
  add_header SSL-FP $ssl_client_fingerprint;
  add_header SSL-IDN $ssl_client_i_dn;
  add_header SSL-Client-Serial $ssl_client_serial;
  add_header SSL-Client-Subject $ssl_client_s_dn;
  add_header SSL-Client-Subject-Legacy $ssl_client_s_dn_legacy;
  add_header SSL-Client-Expires $ssl_client_v_end;
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

For CentOS 7.x curl, need to use `pk12util` command line tool to add the generated client pkcs12 file `/etc/cfssl/clientcerts/cems.msdomain.com.p12` to nssdb database used by curl. Otherwise, curl requests will get a `HTTP/1.1 400 Bad Request` response.

curl with `Initializing NSS with certpath: sql:/etc/pki/nssdb` and showing `NSS: client certificate not found (nickname not specified)` resulting in `HTTP/1.1 400 Bad Request`

```
curl -Ikv https://cems.msdomain.com 
* About to connect() to cems.msdomain.com port 443 (#0)
*   Trying 192.168.0.18...
* Connected to cems.msdomain.com (192.168.0.18) port 443 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
* skipping SSL peer certificate verification
* NSS: client certificate not found (nickname not specified)
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
< HTTP/1.1 400 Bad Request
HTTP/1.1 400 Bad Request
```

Some guides mention passing the client SSL certificate and key on curl command line. But on CentOS 7 it uses nssdb database it seems

```
curl -Ikv --cert /etc/cfssl/clientcerts/cems.msdomain.com.pem --key /etc/cfssl/clientcerts/cems.msdomain.com-key.pem https://cems.msdomain.com
* About to connect() to cems.msdomain.com port 443 (#0)
*   Trying 192.168.0.18...
* Connected to cems.msdomain.com (192.168.0.18) port 443 (#0)
* Initializing NSS with certpath: sql:/etc/pki/nssdb
* unable to load client key: -8178 (SEC_ERROR_BAD_KEY)
* NSS error -8178 (SEC_ERROR_BAD_KEY)
* Peer's public key is invalid.
* Closing connection 0
curl: (58) unable to load client key: -8178 (SEC_ERROR_BAD_KEY)
```

Add the generated client certificate pkcs12 file `/etc/cfssl/clientcerts/cems.msdomain.com.p12` via `pk12util` command line tool. At password prompt just hit enter as no password was assigned.

```
pk12util -d sql:/etc/pki/nssdb -i /etc/cfssl/clientcerts/cems.msdomain.com.p12
```

output

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
< Date: Tue, 15 Sep 2020 01:50:23 GMT
Date: Tue, 15 Sep 2020 01:50:23 GMT
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
< SSL-Client-Verify: SUCCESS
SSL-Client-Verify: SUCCESS
< SSL-FP: ecb64e6417a25e7e7166b63f3691da909600c6db
SSL-FP: ecb64e6417a25e7e7166b63f3691da909600c6db
< SSL-IDN: CN=Intermediate CA,OU=Intermediate CA,L=San Francisco,ST=CA,C=US
SSL-IDN: CN=Intermediate CA,OU=Intermediate CA,L=San Francisco,ST=CA,C=US
< SSL-Client-Serial: 69BD8B8D112B0519C833BE98A48B113855441C11
SSL-Client-Serial: 69BD8B8D112B0519C833BE98A48B113855441C11
< SSL-Client-Subject: CN=cems.msdomain.com,L=San Francisco,ST=CA,C=US
SSL-Client-Subject: CN=cems.msdomain.com,L=San Francisco,ST=CA,C=US
< SSL-Client-Subject-Legacy: /C=US/ST=CA/L=San Francisco/CN=cems.msdomain.com
SSL-Client-Subject-Legacy: /C=US/ST=CA/L=San Francisco/CN=cems.msdomain.com
< SSL-Client-Expires: Sep 11 11:37:00 2030 GMT
SSL-Client-Expires: Sep 11 11:37:00 2030 GMT
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