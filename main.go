package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	commonName string

	kubeconfig     string
	namespace      string
	isCreateSecret bool
	secretName     string

	debug bool
)

func main() {
	flag.StringVar(&commonName, "common-name", "webhook-service.default.svc", "common name for the server certificate")

	flag.BoolVar(&isCreateSecret, "create-secret", false, "create secret")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&secretName, "secret-name", "webhook-server-tls", "secret name for the server certificate")
	flag.StringVar(&namespace, "namespace", "default", "namespace as defined by pod.metadata.namespace")

	flag.BoolVar(&debug, "debug", true, "enable debug")

	flag.Parse()

	// Generate CA certificate and key
	caCert, caKey, err := generateCACertificate()
	if err != nil {
		log.Fatalf("Error generating CA certificate: %s", err)
	}

	// Generate server certificate and key
	serverCert, serverKey, err := generateServerCertificate(caCert, caKey, commonName)
	if err != nil {
		log.Fatalf("Error generating server certificate: %s", err)
	}

	if isCreateSecret {
		// Build the Kubernetes client
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Error building kubeconfig: %s", err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatalf("Error building kubernetes clientset: %s", err)
		}

		// Create Kubernetes secrets
		err = createSecret(clientset, namespace, secretName, map[string][]byte{
			"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}),
			"tls.key": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}),
			"ca.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
		})
		if err != nil {
			log.Fatalf("Error creating server TLS secret: %s", err)
		}
	}

	log.Println("Certificates and secrets generated successfully")

	if debug {
		// // print certificates
		// log.Println("CA Certificate:")
		// log.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})))
		// log.Println("Server Certificate:")
		// log.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})))
		// log.Println("Server Private Key:")
		// log.Println(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})))

		// write certificates to files
		writeToFile("ca.crt", "CERTIFICATE", caCert.Raw)
		writeToFile("ca.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey))
		writeToFile("server.crt", "CERTIFICATE", serverCert.Raw)
		writeToFile("server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
	}
}

func generateCACertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create CA certificate
	caCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2024),
		Subject: pkix.Name{
			Organization: []string{},
			CommonName:   commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

func generateServerCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, commonName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create server certificate
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization: []string{},
			CommonName:   commonName,
		},
		DNSNames:    []string{commonName},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	serverCert, err := x509.ParseCertificate(serverCertBytes)
	if err != nil {
		return nil, nil, err
	}

	return serverCert, serverKey, nil
}

func createSecret(clientset *kubernetes.Clientset, namespace string, name string, data map[string][]byte) error {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}

	_, err := clientset.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	return err
}

func writeToFile(filename, blockType string, data []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating file %s: %s", filename, err)
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: blockType, Bytes: data})
	if err != nil {
		log.Fatalf("Error writing to file %s: %s", filename, err)
	}
	log.Printf("Written %s\n", filename)
}
