# ssc

Self-signed certificates generator.

## Installation

```bash
export PATH=$(go env GOPATH)/bin:$PATH
go get -u github.com/amenzhinsky/ssc
```

## Usage

Generate root certificate:

```bash
ssc -common-name="Root CA" -ca -keyout=ca.key -certout=ca.crt
```

Generate and validate intermediate CA:

```bash
ssc -common-name="Intermediate CA" -ca -cacert=ca.crt -cakey=ca.key-keyout=intermediate.key -certout=intermediate.crt
openssl verify -CAfile=ca.crt intermediate.crt
```

Generate server certificate with [Subject Alternative Names](https://tools.ietf.org/html/rfc5280#section-4.2.1.6) and [Extended Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.12) flags signed by the previously generated intermediate CA:

```bash
ssc -common-name=server -cacert=intermediate.crt -cakey=intermediate.key -san-dns=example.com -eku-server -certout=server.crt -keyout=server.key

openssl verify -CAfile=<(cat ca.crt intermediate.crt) server.crt

cat intermediate.crt server.crt > full.crt
openssl verify -CAfile=ca.crt full.crt 
```

You can use `openssl` to inspect generated certificates:

```bash
openssl x509 -text -noout -in server.crt
```
