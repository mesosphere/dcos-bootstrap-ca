package server

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/mesosphere/dcos-bootstrap-ca/pkg/gen"
	"log"
	"net/http"
	"time"
)

// [Spectre vulnerability] Assume no local compromises
var runtimePsk string
var rootKey *rsa.PrivateKey
var rootCertificate *x509.Certificate

// RunServer configures and launches the CA web service
func RunServer(address, psk string) {
	if err := setSecrets(psk); err != nil {
		log.Fatalf("error storing secrets, have you run init-ca? : %v", err)
	}

	// tls
	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/csr/v1/sign", Sign)

	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  20 * time.Second,
		Addr:         address,
		TLSConfig:    tlsConfig,
		Handler:      mux,
	}

	log.Printf("Serving on %s", address)
	log.Fatal(srv.ListenAndServeTLS(
		gen.StorePath(gen.RootCAFile), gen.StorePath(gen.RootKeyFile)))
}

// setSecrets loads the PSK into memory along with the root key and certificate
// this a security trade off as it opens the program up to memory timing attacks
// but, significantly speeds up signing operations. On kernels vulnerable
// to meltdown, attackers would be able to extract this information from
// the LVS, even if this program read the secrets for every request.
func setSecrets(psk string) error {
	runtimePsk = psk
	certBytes, err := gen.ReadCertificatePEM(gen.StorePath(gen.RootCAFile))
	if err != nil {
		return err
	}
	rootCertificate, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	rootKey, err = gen.ReadPrivateKey(gen.StorePath(gen.RootKeyFile))
	if err != nil {
		return err
	}
	return nil
}

func logRequest(req *http.Request, code, n int) {
	log.Printf("%s %s %s %d %d", req.RemoteAddr, req.Method, req.RequestURI, code, n)
}

func logError(req *http.Request, w http.ResponseWriter, msg string, code int) {
	log.Printf("[error] %s %s %s", req.RemoteAddr, req.RequestURI, msg)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	n, _ := fmt.Fprintln(w, msg)
	logRequest(req, code, n)
}

func index(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		logError(req, w, "method not allowed", http.StatusMethodNotAllowed)
	}

	w.Header().Set("Content-Type", "text/plain")
	n, err := w.Write([]byte("DCOS certificate bootstrap\n"))
	if err != nil {
		log.Fatalf("error writing stream: %v", err)
	}
	logRequest(req, http.StatusOK, n)
}

// SignRequest represents the JSON payload for the /csr/v1/sign endpoint
type SignRequest struct {
	Psk string `json:"psk"`
	Csr string `json:"csr"`
}

//SignResponse represents the JSON response for the /csr/v1/sign endpoint
type SignResponse struct {
	Certificate string `json:"certificate"`
}

// Sign is an HTTP handler which implements CSR signing
func Sign(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		logError(req, w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(req.Body)
	jsonReq := &SignRequest{}
	err := decoder.Decode(jsonReq)

	if err != nil {
		logError(req, w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(runtimePsk) >= 0 && jsonReq.Psk != runtimePsk {
		logError(req, w, "Key is invalid\n", http.StatusUnauthorized)
		return
	}
	csr, err := gen.DecodeAndParsePEM([]byte(jsonReq.Csr))
	if err != nil {
		logError(req, w, "CSR is not valid", http.StatusBadRequest)
		return
	}

	signed, err := gen.Sign(csr, rootCertificate, rootKey)
	if err != nil {
		logError(req, w, "Error signing certificate : "+err.Error(), http.StatusInternalServerError)
		return
	}

	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed})

	j, err := json.Marshal(SignResponse{Certificate: string(b)})
	if err != nil {
		logError(req, w, "Error marshalling JSON : "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	n, err := w.Write(j)
	if err != nil {
		log.Printf("error writing output stream : %s | %s | %v", req.RemoteAddr, req.RequestURI, err)
	}
	logRequest(req, http.StatusOK, n)
}
