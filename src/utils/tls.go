package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/sirupsen/logrus"
)

func TlsConfig(pubkey string) *tls.Config {
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(S2B(pubkey)); !ok {
		logrus.Fatal("Bad Signal Server Public key")
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("tls: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}
			opts := x509.VerifyOptions{
				Roots:         rootCAs, // On the server side, use config.ClientCAs.
				Intermediates: x509.NewCertPool(),
			}

			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}

			_, err := certs[0].Verify(opts)

			return err
		},
	}
}
