package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	ACMEChallengePathPrefix = "/.well-known/acme-challenge/"
)

type LetsEncryptAPIEnv string

const (
	LetsEncryptStaging LetsEncryptAPIEnv = "staging"
	LetsEncryptProd                      = "prod"
)

var letsEncryptAPIs = map[LetsEncryptAPIEnv]string{
	LetsEncryptStaging: "https://acme-staging.api.letsencrypt.org/directory",
	LetsEncryptProd:    "https://acme-v01.api.letsencrypt.org/directory",
}

var cfg struct {
	KeyPath string
	Addr    string
	Domains string
	API     string
	Bits    int
	GenRSA  int
	Revoke  string
}

func init() {
	log.SetFlags(0) // do not log date
	flag.StringVar(&cfg.KeyPath, "key", "", "path to account key")
	flag.StringVar(&cfg.Addr, "addr", "127.0.0.1:81", "challenge server address")
	flag.StringVar(&cfg.Domains, "domains", "", "comma-separated list of up to 100 domain names")
	flag.StringVar(&cfg.API, "api", LetsEncryptProd, "Let's Encrypt acme API endpoint, ['staging', 'prod']")
	flag.IntVar(&cfg.Bits, "bit", 2048, "domain key length")
	flag.IntVar(&cfg.GenRSA, "genrsa", 0, "generate RSA private key of the given bits in length")
	flag.StringVar(&cfg.Revoke, "revoke", "", "path to certificate that need to be revoked")
	flag.Parse()
}

func main() {

	if cfg.GenRSA > 0 {
		key, err := rsa.GenerateKey(rand.Reader, cfg.GenRSA)
		if err != nil {
			log.Fatalf("Failed to generate RSA private key of %d bits: %s", cfg.GenRSA, err)
		}
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}); err != nil {
			log.Fatalln(err)
		}
		return
	}

	domains := strings.Split(cfg.Domains, ",")
	if len(domains) > 100 {
		log.Fatalf("Too many domains (%d > 100)", len(domains))
	}

	// read the account key from stdin if not given in flags
	keyReader := os.Stdin
	var err error
	if cfg.KeyPath != "" {
		keyReader, err = os.Open(cfg.KeyPath)
		if err != nil {
			log.Fatalf("Failed to read account key: %s", err)
		}
	}

	key, err := readRSAKey(keyReader)
	log.Print("Key read and parsed")
	if err != nil {
		log.Fatalf("Failed to parse key: %s", err)
	}

	var (
		api string
		ok  bool
	)
	if api, ok = letsEncryptAPIs[LetsEncryptAPIEnv(cfg.API)]; !ok {
		if !strings.HasPrefix(cfg.API, "https") {
			log.Fatalf("Invalid acme api: %s", cfg.API)
		} else {
			api = cfg.API
		}
	}

	log.Printf("Connecting to ACME server at %s", api)
	acme, err := OpenACME(api, key)
	if err != nil {
		log.Fatalf("Failed to connect to ACME server: %s", err)
	}

	// will revoke certificate and terminate the program
	if cfg.Revoke != "" {
		var yorn string
		fmt.Printf("Confirm revoke of certificate: %s? [y/N]", cfg.Revoke)
		_, err := fmt.Scanf("%s\n", &yorn)
		if err != nil || yorn != "y" {
			os.Exit(1)
		}
		log.Printf("Revoking certificate: %s", cfg.Revoke)
		certFile, err := os.Open(cfg.Revoke)
		if err != nil {
			log.Fatalf("Failed to open certificate: %s", cfg.Revoke)
		}

		certPem, err := ioutil.ReadAll(certFile)
		if err != nil {
			log.Fatalf("Failed to read certificate: %s", cfg.Revoke)
		}
		b, _ := pem.Decode(certPem)
		if b == nil {
			log.Fatal("empty")
		}
		if err = acme.RevokeCert(b.Bytes); err != nil {
			log.Fatalf("Failed to revoke certificate: %s", err)
		}
		log.Println("Certificate revoked successfully")
		os.Exit(0)
	}

	// start the challenge server in background
	log.Printf("Responding to ACME challenges at http://%s", cfg.Addr)
	go http.ListenAndServe(cfg.Addr, acme)

	log.Printf("Registering account key")
	if err := acme.NewReg(); err != nil {
		log.Fatalf("Failed to register account key: %s", err)
	}

	// authorize domains in parallel
	type Done struct {
		Domain string
		Error  error
	}
	ch := make(chan Done)
	for _, domain := range domains {
		go func(domain string) {
			log.Printf("Authorizing domain %s", domain)
			done := Done{Domain: domain}
			if err := acme.NewAuthz(domain); err != nil {
				done.Error = err
			}
			ch <- done
		}(domain)
	}

	// collect authorization result
	failed := false
	for range domains {
		if done := <-ch; done.Error != nil {
			failed = true
			log.Printf("Failed to authorize domain %s: %s", done.Domain, done.Error)
		} else {
			log.Printf("Authorized domain %s", done.Domain)
		}
	}
	if failed {
		log.Fatalln("Some domains failed authorization")
	}

	log.Printf("Generating domain key")
	domainKey, err := rsa.GenerateKey(rand.Reader, cfg.Bits)
	if err != nil {
		log.Fatalf("Failed to generate domain key: %s", err)
	}

	// create certificate signing request
	tpl := &x509.CertificateRequest{DNSNames: domains}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tpl, domainKey)
	if err != nil {
		log.Fatalf("Failed to create certificate request: %s", err)
	}

	log.Printf("Fetching certificates")
	domainCrt, issuerCrt, err := acme.NewCert(csr)
	if err != nil {
		log.Fatalf("Failed to fetch certificates: %s", err)
	}

	// print domain key in PEM to stdout
	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(domainKey),
	}); err != nil {
		log.Fatalln(err)
	}

	// print domain certificate in PEM to stdout
	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: domainCrt.Raw,
	}); err != nil {
		log.Fatalln(err)
	}

	// print issuer certificate in PEM to stdout
	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerCrt.Raw,
	}); err != nil {
		log.Fatalln(err)
	}
}
