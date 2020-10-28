package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	certoutFlag string
	keyoutFlag  string
	cacertFlag  string
	cakeyFlag   string
	daysFlag    int
	caFlag      bool

	algFlag                string
	commonNameFlag         string
	countryFlag            []string
	organizationFlag       []string
	organizationalUnitFlag []string
	localityFlag           []string
	provinceFlag           []string
	streetAddressFlag      []string
	postalCodeFlag         []string

	sanDNSsFlag   []string
	sanEmailsFlag []string
	sanIPsFlag    []net.IP
	sanURIsFlag   []*url.URL

	ekyAnyFlag    bool
	ekuServerFlag bool
	ekuClientFlag bool
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [option...]\n\nOptions:\n",
			filepath.Base(os.Args[0]),
		)
		flag.PrintDefaults()
	}
	flag.StringVar(&algFlag, "alg", "ecp256", "key signing `algorithm` "+
		"(rsa[bits], ecp224, ecp256, ecp384, ecp521, ed25519)")
	flag.StringVar(&certoutFlag, "certout", "server.crt", "certificate output `path`")
	flag.StringVar(&keyoutFlag, "keyout", "server.key", "key output `path`")
	flag.StringVar(&cacertFlag, "cacert", "", "`path` to CA certificate")
	flag.StringVar(&cakeyFlag, "cakey", "", "`path` to CA key")

	// commons
	flag.IntVar(&daysFlag, "days", 365, "certificate valid for n `days`")
	flag.BoolVar(&caFlag, "ca", false, "is certificate authority")

	// subject
	flag.StringVar(&commonNameFlag, "common-name", "", "common `name`")
	flag.Var((*stringsValue)(&countryFlag), "country", "country `code`")
	flag.Var((*stringsValue)(&organizationFlag), "organization", "organization `name`")
	flag.Var((*stringsValue)(&organizationalUnitFlag), "organizational-unit", "organizational unit `name`")
	flag.Var((*stringsValue)(&localityFlag), "locality", "locality `name`")
	flag.Var((*stringsValue)(&provinceFlag), "province", "province `name`")
	flag.Var((*stringsValue)(&streetAddressFlag), "street-address", "street `address`")
	flag.Var((*stringsValue)(&postalCodeFlag), "postal-code", "postal `code`")

	// SANs
	flag.Var((*stringsValue)(&sanDNSsFlag), "san-dns", "DNS `name`")
	flag.Var((*stringsValue)(&sanEmailsFlag), "san-email", "email `address`")
	flag.Var((*ipsValue)(&sanIPsFlag), "san-ip", "ip `address`")
	flag.Var((*urlsValue)(&sanURIsFlag), "san-uri", "resource `identifier`")

	// EKUs
	flag.BoolVar(&ekyAnyFlag, "eky-any", false, "enable any extended key")
	flag.BoolVar(&ekuClientFlag, "eku-client", false, "enable client authentication")
	flag.BoolVar(&ekuServerFlag, "eku-server", false, "enable server authentication")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	pub, key, err := genKeyPair(algFlag)
	if err != nil {
		return fmt.Errorf("cannot generate key pair: %w", err)
	}

	sn, err := genSerialNumber()
	if err != nil {
		return err
	}

	cert := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			Country:            countryFlag,
			Organization:       organizationFlag,
			OrganizationalUnit: organizationalUnitFlag,
			Locality:           localityFlag,
			Province:           provinceFlag,
			StreetAddress:      streetAddressFlag,
			PostalCode:         postalCodeFlag,
			CommonName:         commonNameFlag,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, daysFlag),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,

		DNSNames:       sanDNSsFlag,
		EmailAddresses: sanEmailsFlag,
		IPAddresses:    sanIPsFlag,
		URIs:           sanURIsFlag,
	}

	cacert, cakey := &cert, key
	if cacertFlag != "" {
		cacert, err = parseCert(cacertFlag)
		if err != nil {
			return fmt.Errorf("cannot parse cacert: %w", err)
		}
		cakey, err = parseKey(cakeyFlag)
		if err != nil {
			return fmt.Errorf("cannot parse cakey: %w", err)
		}
	}

	if _, ok := key.(*rsa.PrivateKey); ok {
		cert.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if caFlag {
		cert.IsCA = true
		cert.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if ekyAnyFlag {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageAny)
	}
	if ekuServerFlag {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if ekuClientFlag {
		cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, cacert, pub, cakey)
	if err != nil {
		return err
	}

	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	cf, err := os.OpenFile(certoutFlag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer cf.Close()

	kf, err := os.OpenFile(keyoutFlag, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer kf.Close()

	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	if err := pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: b}); err != nil {
		return err
	}

	return nil
}

func genKeyPair(alg string) (interface{}, interface{}, error) {
	switch {
	case strings.HasPrefix(alg, "rsa"):
		bits, err := strconv.ParseInt(alg[3:], 10, 0)
		if err != nil {
			return nil, nil, errors.New("cannot parse RSA bits")
		}
		pk, err := rsa.GenerateKey(rand.Reader, int(bits))
		if err != nil {
			return nil, nil, err
		}
		return pk.Public(), pk, nil
	case strings.HasPrefix(alg, "ec"):
		var c elliptic.Curve
		switch alg[2:] {
		case "p224":
			c = elliptic.P224()
		case "p256":
			c = elliptic.P256()
		case "p384":
			c = elliptic.P384()
		case "p521":
			c = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("ambiguous elliptic curve type: %s", alg[2:])
		}
		pk, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return pk.Public(), pk, nil
	case alg == "ed25519":
		return ed25519.GenerateKey(rand.Reader)
	default:
		return nil, nil, fmt.Errorf("ambiguous key algorithm: %s", algFlag)
	}
}

func genSerialNumber() (*big.Int, error) {
	max := big.NewInt(1)
	max = max.Lsh(max, 160)
	max.Add(max, big.NewInt(-1))
	return rand.Int(rand.Reader, max)
}

func parseCert(path string) (*x509.Certificate, error) {
	b, err := parsePEM(path)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(b)
}

func parseKey(path string) (interface{}, error) {
	b, err := parsePEM(path)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(b)
}

func parsePEM(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	return block.Bytes, nil
}

type stringsValue []string

func (v *stringsValue) Set(s string) error {
	*v = append(*v, s)
	return nil
}

func (v *stringsValue) String() string {
	return fmt.Sprintf("%v", []string(*v))
}

type ipsValue []net.IP

func (v *ipsValue) Set(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return errors.New("cannot parse id address")
	}
	*v = append(*v, ip)
	return nil
}

func (v *ipsValue) String() string {
	return fmt.Sprintf("%v", []net.IP(*v))
}

type urlsValue []*url.URL

func (v *urlsValue) Set(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	*v = append(*v, u)
	return nil
}

func (v *urlsValue) String() string {
	return fmt.Sprintf("%v", []*url.URL(*v))
}
