package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// TestCertificates validates the generated certificates.
func TestCertificates(t *testing.T) {
	// Read CA certificate
	caCertPEM, err := os.ReadFile("ca.crt")
	if err != nil {
		t.Fatalf("Error reading CA certificate: %s", err)
	}

	// Read CA key
	// caKeyPEM, err := os.ReadFile("ca.key")
	// if err != nil {
	// 	t.Fatalf("Error reading CA key: %s", err)
	// }

	// Read server certificate
	serverCertPEM, err := os.ReadFile("server.crt")
	if err != nil {
		t.Fatalf("Error reading server certificate: %s", err)
	}

	// // Read server key
	// serverKeyPEM, err := os.ReadFile("server.key")
	// if err != nil {
	// 	t.Fatalf("Error reading server key: %s", err)
	// }

	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("Error parsing CA certificate: %s", err)
	}

	// Parse server certificate
	serverCertBlock, _ := pem.Decode(serverCertPEM)
	if serverCertBlock == nil || serverCertBlock.Type != "CERTIFICATE" {
		t.Fatalf("Failed to decode server certificate PEM")
	}
	serverCert, err := x509.ParseCertificate(serverCertBlock.Bytes)
	if err != nil {
		t.Fatalf("Error parsing server certificate: %s", err)
	}

	// Validate the server certificate is signed by the CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := serverCert.Verify(opts); err != nil {
		t.Fatalf("Failed to verify server certificate: %s", err)
	}

	t.Log("Server certificate is valid and signed by the CA")
}
