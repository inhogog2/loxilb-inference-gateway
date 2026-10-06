// Fixtures for scenarios that qualify the backend leg of an end-to-end HTTPS
// rule. Standard library only, built by the scenario that uses it:
//
//	go build -o fixture fixture.go
//
//	fixture ca    -out <base> [-alg rsa|ecdsa]
//	fixture leaf  -ca <base> -out <base> [-alg rsa|ecdsa] [-bits n]
//	              [-ip a,b] [-dns x,y] [-usage server|client|both] [-expired]
//	fixture serve -name <n> -port <p> -cert <f> -key <f> -receipts <f>
//	              [-clientca <f>] [-require]
//	fixture pair  -ca <f> -gate <f> [-http1] <url> <url>
//
// ca and leaf write <base>.crt, <base>.key and <base>.fp, the SHA-256 of the
// certificate in hex.
//
// serve answers every request, over HTTP/1.1 or HTTP/2, with one line that
// says what the server saw of its peer:
//
//	name=<n> proto=<HTTP/x> peer=<SHA-256 of the client certificate|none> sni=<name|none> nonce=<nonce>
//
// and appends the nonce of the request (query argument "nonce") to the
// receipt file. A nonce in the receipt file is a request that reached this
// server; a nonce that is not there did not.
//
// pair is a client that sends two requests on one connection: the first at
// once, the second when the gate file exists. It prints one line for each:
//
//	first|second status=<n> reused=<true|false> <the answer>
//
// reused says whether the request travelled on a connection the client had
// already used.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: fixture ca|leaf|serve|pair [arguments]")
	}
	switch os.Args[1] {
	case "ca":
		cmdCA(os.Args[2:])
	case "leaf":
		cmdLeaf(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "pair":
		cmdPair(os.Args[2:])
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func newKey(alg string, bits int) crypto.Signer {
	switch alg {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			log.Fatal(err)
		}
		return k
	case "ecdsa":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		return k
	}
	log.Fatalf("unknown key algorithm %q", alg)
	return nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		log.Fatal(err)
	}
	return n
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func writePair(base string, der []byte, key crypto.Signer) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	files := []struct {
		ext  string
		data []byte
		perm os.FileMode
	}{
		{".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644},
		{".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600},
		{".fp", []byte(fingerprint(der) + "\n"), 0644},
	}
	if err := os.MkdirAll(filepath.Dir(base), 0755); err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(base+f.ext, f.data, f.perm); err != nil {
			log.Fatal(err)
		}
	}
}

func readPair(base string) (*x509.Certificate, crypto.Signer) {
	crtPEM, err := os.ReadFile(base + ".crt")
	if err != nil {
		log.Fatal(err)
	}
	keyPEM, err := os.ReadFile(base + ".key")
	if err != nil {
		log.Fatal(err)
	}
	cb, _ := pem.Decode(crtPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		log.Fatalf("%s: not a PEM certificate and key", base)
	}
	crt, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return crt, key.(crypto.Signer)
}

func cmdCA(args []string) {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	out := fs.String("out", "", "output base name")
	alg := fs.String("alg", "rsa", "rsa or ecdsa")
	fs.Parse(args)
	if *out == "" {
		log.Fatal("ca: -out is required")
	}
	key := newKey(*alg, 2048)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "scenario CA " + filepath.Base(*out)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}
	writePair(*out, der, key)
}

func cmdLeaf(args []string) {
	fs := flag.NewFlagSet("leaf", flag.ExitOnError)
	caBase := fs.String("ca", "", "base name of the issuing CA")
	out := fs.String("out", "", "output base name")
	alg := fs.String("alg", "rsa", "rsa or ecdsa")
	bits := fs.Int("bits", 2048, "RSA key size")
	ips := fs.String("ip", "", "IP subject alternative names, comma separated")
	names := fs.String("dns", "", "DNS subject alternative names, comma separated")
	usage := fs.String("usage", "server", "server, client or both")
	expired := fs.Bool("expired", false, "validity ended yesterday")
	fs.Parse(args)
	if *caBase == "" || *out == "" {
		log.Fatal("leaf: -ca and -out are required")
	}
	caCrt, caKey := readPair(*caBase)
	key := newKey(*alg, *bits)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: filepath.Base(*out)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if *expired {
		tmpl.NotBefore = now.Add(-48 * time.Hour)
		tmpl.NotAfter = now.Add(-24 * time.Hour)
	}
	switch *usage {
	case "server":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "both":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		log.Fatalf("leaf: unknown usage %q", *usage)
	}
	for _, s := range strings.Split(*ips, ",") {
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			log.Fatalf("leaf: %q is not an IP address", s)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	for _, s := range strings.Split(*names, ",") {
		if s != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCrt, key.Public(), caKey)
	if err != nil {
		log.Fatal(err)
	}
	writePair(*out, der, key)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	name := fs.String("name", "", "name the server answers with")
	port := fs.String("port", "", "listening port")
	cert := fs.String("cert", "", "server certificate")
	key := fs.String("key", "", "server private key")
	clientCA := fs.String("clientca", "", "CA a client certificate must chain to")
	require := fs.Bool("require", false, "refuse a client that presents no certificate")
	receipts := fs.String("receipts", "", "file the nonce of every request is appended to")
	fs.Parse(args)
	if *name == "" || *port == "" || *cert == "" || *key == "" || *receipts == "" {
		log.Fatal("serve: -name, -port, -cert, -key and -receipts are required")
	}

	// A client certificate is asked for in every mode, so that the server can
	// report one a client sends without being required to.
	cfg := &tls.Config{ClientAuth: tls.RequestClientCert}
	if *clientCA != "" {
		caPEM, err := os.ReadFile(*clientCA)
		if err != nil {
			log.Fatal(err)
		}
		cfg.ClientCAs = x509.NewCertPool()
		if !cfg.ClientCAs.AppendCertsFromPEM(caPEM) {
			log.Fatalf("serve: no certificate in %s", *clientCA)
		}
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		if *require {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		peer, sni := "none", "none"
		if r.TLS != nil {
			if len(r.TLS.PeerCertificates) > 0 {
				peer = fingerprint(r.TLS.PeerCertificates[0].Raw)
			}
			if r.TLS.ServerName != "" {
				sni = r.TLS.ServerName
			}
		}
		nonce := r.URL.Query().Get("nonce")
		if nonce != "" {
			mu.Lock()
			f, err := os.OpenFile(*receipts, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				fmt.Fprintln(f, nonce)
				f.Close()
			}
			mu.Unlock()
		}
		fmt.Fprintf(w, "name=%s proto=%s peer=%s sni=%s nonce=%s\n", *name, r.Proto, peer, sni, nonce)
	})
	srv := &http.Server{Addr: ":" + *port, Handler: mux, TLSConfig: cfg}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

func cmdPair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	ca := fs.String("ca", "", "CA the server certificate must chain to")
	gate := fs.String("gate", "", "file whose existence releases the second request")
	http1 := fs.Bool("http1", false, "speak HTTP/1.1 only")
	fs.Parse(args)
	if *ca == "" || *gate == "" || fs.NArg() != 2 {
		log.Fatal("pair: -ca, -gate and two URLs are required")
	}
	caPEM, err := os.ReadFile(*ca)
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("pair: no certificate in %s", *ca)
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: !*http1,
		MaxConnsPerHost:   1,
		IdleConnTimeout:   5 * time.Minute,
	}
	if *http1 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

	one := func(label, url string) {
		reused := false
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			log.Fatal(err)
		}
		resp, err := client.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
		if err != nil {
			fmt.Printf("%s status=000 reused=%t %v\n", label, reused, err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("%s status=%d reused=%t %s\n", label, resp.StatusCode, reused, strings.TrimSpace(string(body)))
	}

	one("first", fs.Arg(0))
	for i := 0; i < 600; i++ {
		if _, err := os.Stat(*gate); !errors.Is(err, os.ErrNotExist) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	one("second", fs.Arg(1))
}
