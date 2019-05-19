/*-
 * Copyright 2017 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io"
	"os"
	"regexp"

	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
)

var (
	app = kingpin.New("jwk-keygen", "A command-line utility to generate public/pirvate keypairs in JWK format.")

	use = app.Flag("use", "Desrired key use").Required().Enum("enc", "sig")
	alg = app.Flag("alg", "Generate key to be used for ALG").Required().Enum(
		// `sig`
		string(jose.ES256), string(jose.ES384), string(jose.ES512), string(jose.EdDSA),
		string(jose.RS256), string(jose.RS384), string(jose.RS512), string(jose.PS256), string(jose.PS384), string(jose.PS512),
		// `enc`
		string(jose.RSA1_5), string(jose.RSA_OAEP), string(jose.RSA_OAEP_256),
		string(jose.ECDH_ES), string(jose.ECDH_ES_A128KW), string(jose.ECDH_ES_A192KW), string(jose.ECDH_ES_A256KW),
	)
	bits       = app.Flag("bits", "Key size in bits").Int()
	kid        = app.Flag("kid", "Key ID").String()
	kidRand    = app.Flag("kid-rand", "Generate random Key ID").Bool()
	jwks       = app.Flag("jwks", "Generate as JWKS too").Bool()
	pemOut     = app.Flag("pem", "Generate as PEM too").Bool()
	pemBody    = app.Flag("pem-body", "Generate as PEM body too").Bool()
	pemOneLine = app.Flag("pem-one-line", "Generate as PEM with one-line too").Bool()
	format     = app.Flag("format", "Out JSON with format").Bool()
)

// KeygenSig generates keypair for corresponding SignatureAlgorithm.
func KeygenSig(alg jose.SignatureAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		keylen := map[jose.SignatureAlgorithm]int{
			jose.ES256: 256,
			jose.ES384: 384,
			jose.ES512: 521, // sic!
			jose.EdDSA: 256,
		}
		if bits != 0 && bits != keylen[alg] {
			return nil, nil, errors.New("this `alg` does not support arbitrary key length")
		}
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
	}
	switch alg {
	case jose.ES256:
		// The cryptographic operations are implemented using constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return key.Public(), key, err
	case jose.ES384:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return key.Public(), key, err
	case jose.ES512:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return key.Public(), key, err
	case jose.EdDSA:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		return pub, key, err
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `sig`")
	}
}

// KeygenEnc generates keypair for corresponding KeyAlgorithm.
func KeygenEnc(alg jose.KeyAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	case jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		var crv elliptic.Curve
		switch bits {
		case 0, 256:
			crv = elliptic.P256()
		case 384:
			crv = elliptic.P384()
		case 521:
			crv = elliptic.P521()
		default:
			return nil, nil, errors.New("unknown elliptic curve bit length, use one of 256, 384, 521")
		}
		key, err := ecdsa.GenerateKey(crv, rand.Reader)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `enc`")
	}
}

func pemBlockForKey(priv crypto.PrivateKey) ([]byte, error) {
	var pemBlock *pem.Block
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		}
	default:
		fmt.Println(k)
		return nil, errors.New("Uknown private key type")
	}
	var buf bytes.Buffer
	err := pem.Encode(&buf, pemBlock)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func toBody(b []byte) []byte {
	s := string(b)
	rep := regexp.MustCompile("(?m)^\\-{5}.*\\-{5}$")
	rep2 := regexp.MustCompile("\\n")
	s = rep.ReplaceAllString(s, "")
	return []byte(rep2.ReplaceAllString(s, ""))
}

func toOneLine(b []byte) []byte {
	s := string(b)
	rep := regexp.MustCompile("\\n")
	return []byte(rep.ReplaceAllString(s, "\\n"))
}

func pemBlockForPublicKey(pubKey crypto.PublicKey) ([]byte, error) {
	var pemBlock *pem.Block
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		asn1Bytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		pemBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}
	case *ecdsa.PublicKey:
		asn1Bytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		pemBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}
	default:
		return nil, errors.New("Uknown public key type")
	}
	var buf bytes.Buffer
	err := pem.Encode(&buf, pemBlock)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func formatJSON(b []byte) []byte {
	var buf bytes.Buffer
	err := json.Indent(&buf, b, "", "    ")
	if err != nil {
		return b
	}
	return buf.Bytes()
}

func main() {
	app.Version("v2")
	kingpin.MustParse(app.Parse(os.Args[1:]))

	if *kidRand {
		if *kid == "" {
			b := make([]byte, 5)
			_, err := rand.Read(b)
			app.FatalIfError(err, "can't Read() crypto/rand")
			*kid = base32.StdEncoding.EncodeToString(b)
		} else {
			app.FatalUsage("can't combine --kid and --kid-rand")
		}
	}

	var privKey crypto.PublicKey
	var pubKey crypto.PrivateKey
	var err error
	switch *use {
	case "sig":
		pubKey, privKey, err = KeygenSig(jose.SignatureAlgorithm(*alg), *bits)
	case "enc":
		pubKey, privKey, err = KeygenEnc(jose.KeyAlgorithm(*alg), *bits)
	}
	app.FatalIfError(err, "unable to generate key")

	priv := jose.JSONWebKey{Key: privKey, KeyID: *kid, Algorithm: *alg, Use: *use}
	pub := jose.JSONWebKey{Key: pubKey, KeyID: *kid, Algorithm: *alg, Use: *use}

	if priv.IsPublic() || !pub.IsPublic() || !priv.Valid() || !pub.Valid() {
		app.Fatalf("invalid keys were generated")
	}

	privJS, err := priv.MarshalJSON()
	app.FatalIfError(err, "can't Marshal private key to JSON")
	pubJS, err := pub.MarshalJSON()
	app.FatalIfError(err, "can't Marshal public key to JSON")

	if *format {
		pubJS = formatJSON(pubJS)
		privJS = formatJSON(privJS)
	}

	var pubJSJWKS []byte
	var privJSJWKS []byte

	if *jwks {
		privJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{priv}}
		pubJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}}

		privJSJWKS, err = json.Marshal(privJWKS)
		app.FatalIfError(err, "can't Marshal private key with JWKS to JSON")
		pubJSJWKS, err = json.Marshal(pubJWKS)
		app.FatalIfError(err, "can't Marshal public key with JWKS to JSON")

		if *format {
			pubJSJWKS = formatJSON(pubJSJWKS)
			privJSJWKS = formatJSON(privJSJWKS)
		}
	}

	var privPEM []byte
	var pubPEM []byte

	if *pemOut || *pemBody || *pemOneLine {
		privPEM, err = pemBlockForKey(privKey)
		app.FatalIfError(err, "can't Marshal private key with to PEM")
		pubPEM, err = pemBlockForPublicKey(pubKey)
		app.FatalIfError(err, "can't Marshal public key to PEM")
	}

	if *kid == "" {
		fmt.Printf("==> jwk_%s-pub.json <==\n", *alg)
		fmt.Println(string(pubJS))
		fmt.Printf("==> jwk_%s.json <==\n", *alg)
		fmt.Println(string(privJS))

		if *jwks {
			fmt.Printf("==> jwks_%s-pub.json <==\n", *alg)
			fmt.Println(string(pubJSJWKS))
			fmt.Printf("==> jwks_%s.json <==\n", *alg)
			fmt.Println(string(privJSJWKS))
		}

		if *pemOut {
			fmt.Printf("==> pem_%s-pub.pem <==\n", *alg)
			fmt.Println(string(pubPEM))
			fmt.Printf("==> pem_%s.pem <==\n", *alg)
			fmt.Println(string(privPEM))
		}

		if *pemBody {
			fmt.Printf("==> pem-body-%s-pub.pem <==\n", *alg)
			fmt.Println(string(toBody(pubPEM)))
			fmt.Printf("==> pem-body-%s.pem <==\n", *alg)
			fmt.Println(string(toBody(privPEM)))
		}

		if *pemOneLine {
			fmt.Printf("==> pem-one-line-%s-pub.pem <==\n", *alg)
			fmt.Println(string(toOneLine(pubPEM)))
			fmt.Printf("==> pem-one-line-%s.pem <==\n", *alg)
			fmt.Println(string(toOneLine(privPEM)))
		}
	} else {
		// JWK Thumbprint (RFC7638) is not used for key id because of
		// lack of canonical representation.
		fname := fmt.Sprintf("jwk_%s_%s_%s", *use, *alg, *kid)
		err = writeNewFile(fname+"-pub.json", pubJS, 0444)
		app.FatalIfError(err, "can't write public key with JWK to file %s-pub.json", fname)
		fmt.Printf("Written public key with JWK to %s-pub.json\n", fname)
		err = writeNewFile(fname+".json", privJS, 0400)
		app.FatalIfError(err, "cant' write private key with JWK to file %s.json", fname)
		fmt.Printf("Written private key with JWK to %s.json\n", fname)

		if *jwks {
			fname := fmt.Sprintf("jwks_%s_%s_%s", *use, *alg, *kid)
			err = writeNewFile(fname+"-pub.json", pubJSJWKS, 0444)
			app.FatalIfError(err, "can't write public key with JWKS to file %s-pub.json", fname)
			fmt.Printf("Written public key with JWKS to %s-pub.json\n", fname)
			err = writeNewFile(fname+".json", privJSJWKS, 0400)
			app.FatalIfError(err, "cant' write private key with JWKS to file %s.json", fname)
			fmt.Printf("Written private key with JWKS to %s.json\n", fname)
		}

		if *pemOut {
			fname = fmt.Sprintf("pem_%s_%s_%s", *use, *alg, *kid)
			err = writeNewFile(fname+"-pub.pem", pubPEM, 0444)
			app.FatalIfError(err, "can't write public key with PEM to file %s-pub.pem", fname)
			fmt.Printf("Written public key with PEM to %s-pub.pem\n", fname)
			err = writeNewFile(fname+".pem", privPEM, 0400)
			app.FatalIfError(err, "cant' write private key with PEM to file %s.pem", fname)
			fmt.Printf("Written private key to %s.pem\n", fname)
		}

		if *pemBody {
			fname = fmt.Sprintf("pem-body_%s_%s_%s", *use, *alg, *kid)
			err = writeNewFile(fname+"-pub.pem", toBody(pubPEM), 0444)
			app.FatalIfError(err, "can't write public key with PEM to file %s-pub.pem", fname)
			fmt.Printf("Written public key with PEM to %s-pub.pem\n", fname)
			err = writeNewFile(fname+".pem", toBody(privPEM), 0400)
			app.FatalIfError(err, "cant' write private key with PEM to file %s.pem", fname)
			fmt.Printf("Written private key to %s.pem\n", fname)
		}

		if *pemOneLine {
			fname = fmt.Sprintf("pem-one-line_%s_%s_%s", *use, *alg, *kid)
			err = writeNewFile(fname+"-pub.pem", toOneLine(pubPEM), 0444)
			app.FatalIfError(err, "can't write public key with PEM to file %s-pub.pem", fname)
			fmt.Printf("Written public key with PEM to %s-pub.pem\n", fname)
			err = writeNewFile(fname+".pem", toOneLine(privPEM), 0400)
			app.FatalIfError(err, "cant' write private key with PEM to file %s.pem", fname)
			fmt.Printf("Written private key to %s.pem\n", fname)
		}
	}
}

// writeNewFile is shameless copy-paste from ioutil.WriteFile with a bit
// different flags for OpenFile.
func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}
