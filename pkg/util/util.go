package util

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
)

func GetCertPool(paths []string) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("invalid empty list of Root CAs file paths")
	}
	pool := x509.NewCertPool()
	for _, path := range paths {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}

func GetSecretValue(source *options.SecretSource) ([]byte, error) {
	switch {
	case len(source.Value) > 0 && source.FromEnv == "" && source.FromFile == "":
		value := make([]byte, base64.StdEncoding.DecodedLen(len(source.Value)))
		decoded, err := base64.StdEncoding.Decode(value, source.Value)
		return value[:decoded], err
	case len(source.Value) == 0 && source.FromEnv != "" && source.FromFile == "":
		return []byte(os.Getenv(source.FromEnv)), nil
	case len(source.Value) == 0 && source.FromEnv == "" && source.FromFile != "":
		return ioutil.ReadFile(source.FromFile)
	default:
		return nil, errors.New("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile")
	}
}
