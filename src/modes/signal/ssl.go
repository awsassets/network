package signal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/types"
	"github.com/disembark/network/src/utils"
	"github.com/sirupsen/logrus"
)

var (
	ErrBadJoinToken = fmt.Errorf("bad join token")
)

func GenerateNode(config *configure.Config, name string) (*configure.Config, error) {
	cert, priv, err := GenerateClientTls(config)
	if err != nil {
		return nil, err
	}

	jt, err := GenerateClientJoinToken(config, configure.ModeNode, name)
	if err != nil {
		return nil, err
	}

	return configure.NewFromFile(configure.Config{
		LogLevel: "info",
		Mode:     configure.ModeNode,
		TunBind:  "dynamic",
		SignalServers: append(config.SignalServers, configure.SignalServer{
			Name:         config.Name,
			AccessPoints: config.AdvertiseAddresses,
		}),
		Config:                fmt.Sprintf("%s.%s.yaml", name, configure.ModeNode),
		ClientPublicKey:       utils.B2S(cert),
		ClientPrivateKey:      utils.B2S(priv),
		SignalServerPublicKey: config.SignalServerPublicKey,
		JoinToken:             jt,
		Name:                  name,
		DnsAliases:            []string{name},
		Bind:                  "0.0.0.0:7777",
		AdvertiseAddresses:    []string{"127.0.0.1:7777"},
	}), nil
}

func GenerateSignal(config *configure.Config, name string) (*configure.Config, error) {
	return configure.NewFromFile(configure.Config{
		LogLevel: "info",
		Mode:     configure.ModeSignal,
		SignalServers: append(config.SignalServers, configure.SignalServer{
			Name:         config.Name,
			AccessPoints: config.AdvertiseAddresses,
		}),
		Config:                 fmt.Sprintf("%s.%s.yaml", name, configure.ModeSignal),
		SignalServerPublicKey:  config.SignalServerPublicKey,
		SignalServerPrivateKey: config.SignalServerPrivateKey,
		TokenKey:               config.TokenKey,
		Name:                   name,
		DnsAliases:             []string{name},
		Bind:                   "0.0.0.0:7777",
		AdvertiseAddresses:     []string{"127.0.0.1:7777"},
	}), nil
}

func GenerateRelayServer(config *configure.Config, name string) (*configure.Config, error) {
	return configure.NewFromFile(configure.Config{
		LogLevel: "info",
		Mode:     configure.ModeRelayServer,
		SignalServers: append(config.SignalServers, configure.SignalServer{
			Name:         config.Name,
			AccessPoints: config.AdvertiseAddresses,
		}),
		Config:                 fmt.Sprintf("%s.%s.yaml", name, configure.ModeRelayServer),
		SignalServerPublicKey:  config.SignalServerPublicKey,
		SignalServerPrivateKey: config.SignalServerPrivateKey,
		TokenKey:               config.TokenKey,
		Name:                   name,
		DnsAliases:             []string{name},
		Bind:                   "0.0.0.0:7777",
		AdvertiseAddresses:     []string{"127.0.0.1:7777"},
		RelayHttpBind:          "0.0.0.0:3000",
	}), nil
}

func GenerateRelayClient(config *configure.Config, name string) (*configure.Config, error) {
	cert, priv, err := GenerateClientTls(config)
	if err != nil {
		return nil, err
	}

	jt, err := GenerateClientJoinToken(config, configure.ModeRelayClient, name)
	if err != nil {
		return nil, err
	}

	return configure.NewFromFile(configure.Config{
		LogLevel: "info",
		Mode:     configure.ModeRelayClient,
		TunBind:  "dynamic",
		SignalServers: append(config.SignalServers, configure.SignalServer{
			Name:         config.Name,
			AccessPoints: config.AdvertiseAddresses,
		}),
		Config:                fmt.Sprintf("%s.%s.yaml", name, configure.ModeRelayClient),
		ClientPublicKey:       utils.B2S(cert),
		ClientPrivateKey:      utils.B2S(priv),
		SignalServerPublicKey: config.SignalServerPublicKey,
		JoinToken:             jt,
		Name:                  name,
		DnsAliases:            []string{name},
	}), nil
}

func GenerateClientJoinToken(config *configure.Config, mode configure.Mode, name string) (string, error) {
	key, err := hex.DecodeString(config.TokenKey)
	if err != nil {
		return "", err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return "", err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	data, _ := json.Marshal(types.JoinTokenPayload{
		CreatedAt: time.Now(),
		Mode:      mode,
		Name:      name,
	})

	return hex.EncodeToString(gcm.Seal(nonce, nonce, data, nil)), nil
}

func VerifyClientJoinToken(config *configure.Config, tkn string) (types.JoinTokenPayload, error) {
	key, err := hex.DecodeString(config.TokenKey)
	if err != nil {
		return types.JoinTokenPayload{}, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return types.JoinTokenPayload{}, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return types.JoinTokenPayload{}, err
	}
	ciphertext, err := hex.DecodeString(tkn)
	if err != nil {
		return types.JoinTokenPayload{}, err
	}

	nonceSize := gcm.NonceSize()

	if len(ciphertext) < nonceSize {
		return types.JoinTokenPayload{}, ErrBadJoinToken
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return types.JoinTokenPayload{}, ErrBadJoinToken
	}

	pl := types.JoinTokenPayload{}
	err = json.Unmarshal(plaintext, &pl)

	return pl, err
}

func GenerateClientTls(config *configure.Config) ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(utils.S2B(config.SignalServerPrivateKey))

	caPrivKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes)

	certBytes, err := x509.CreateCertificate(rand.Reader, Cert, CaCert, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := bytes.NewBuffer(nil)
	_ = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privKeyData, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	privKeyPEM := bytes.NewBuffer(nil)
	_ = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyData,
	})

	return certPEM.Bytes(), privKeyPEM.Bytes(), nil
}

func GenerateCaTls(config *configure.Config) {
	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logrus.Fatalf("Failed to generate private key: %v", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, CaCert, CaCert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		logrus.Fatalf("Failed to generate private key: %v", err)
	}

	caPEM := bytes.NewBuffer(nil)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	privKeyData, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
	if err != nil {
		logrus.Fatalf("Failed to generate private key: %v", err)
	}

	caPrivKeyPEM := bytes.NewBuffer(nil)
	_ = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyData,
	})

	config.SignalServerPublicKey = caPEM.String()
	config.SignalServerPrivateKey = caPrivKeyPEM.String()

	if err := config.Save(); err != nil {
		logrus.Fatalf("Failed to generate private key: %v", err)
	}
}

var Cert = &x509.Certificate{
	SerialNumber: big.NewInt(1658),
	Subject: pkix.Name{
		Organization: []string{"Disembark."},
	},
	NotBefore:    time.Now(),
	NotAfter:     time.Now().AddDate(10, 0, 0),
	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:     x509.KeyUsageDigitalSignature,
}

var CaCert = &x509.Certificate{
	SerialNumber: big.NewInt(2019),
	Subject: pkix.Name{
		Organization: []string{"Disembark."},
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(10, 0, 0),
	IsCA:                  true,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	BasicConstraintsValid: true,
}
