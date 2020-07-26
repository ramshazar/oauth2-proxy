package util

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

// Test certificate created with an OpenSSL command in the following form:
// openssl req -x509 -newkey rsa:4096 -keyout key-unused.pem -out cert.pem -nodes -subj "/CN=oauth-proxy test ca"

var (
	testCA1Subj = "CN=oauth-proxy test ca"
	testCA1     = `-----BEGIN CERTIFICATE-----
MIICuTCCAaGgAwIBAgIFAKuKEWowDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAxMT
b2F1dGgtcHJveHkgdGVzdCBjYTAeFw0xNzEwMjQyMDExMzJaFw0xOTEwMjQyMDEx
MzJaMB4xHDAaBgNVBAMTE29hdXRoLXByb3h5IHRlc3QgY2EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC5/kmgKNiECuxlj27yTWBWOMVvIB0AaRhQrMA7
3iSCk/SHhaTabUuXUGRwmCAewT/y9oX3rTdfnSPCn7praU/27lRFBgOGFrTzAZH6
voisF54I3ZxWZgHDJ/ig/KFwd0Y8OATj9/k9uAJSCe6aT7BouJPZVWNGF2dF5BOJ
EwFsJiN2s8HpF14DhxFOMMtlckdMHGxi3wj3E/hBCfGvGGU4Wezz48vEWWC1ajWM
qVq2vVWi1bcNft8FjWa5wTGpdlDQJM7yvKYJPwRkEjgIXtF1ra3JM3WTTFZO9Yhd
QXwO7IWRTdTaypKTNbTDKuWQZsm7xQM9sNcFkukGb3o+uBpLAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAHJNrUfHhN7VOUF60pG8sOEkx0ztjbtbYMj2N9Kb0oSya+re
Kmb2Z4JgyV7XHCZ03Jch6L7UBI3Y6/Lp1zdwU03LFayVUchLkvFonoXpRRP5UFYN
+36xP3ZL1qBYFphARsCk6/tl36czH4oF5gTlhWCRy3upNzn+INk467hnCKt5xuse
zhm+xQv/VN1poI0S/oCg9HLA9iKpoqGJByN32yoFr3QViLPqkmJ1v8EiH0Ns+1m3
pP5YlVqdRCVrxgT80PIMsvQhfcuIrbbeiRDEUdEX7FqebuGCEa2757MTdW7UYQiB
7kgECMnwAOlJME8aDKnmTBajaMy6xCSC87V7wps=
-----END CERTIFICATE-----
`
	testCA2Subj = "CN=oauth-proxy second test ca"
	testCA2     = `-----BEGIN CERTIFICATE-----
MIICxzCCAa+gAwIBAgIFAKuMKewwDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAxMa
b2F1dGgtcHJveHkgc2Vjb25kIHRlc3QgY2EwHhcNMTcxMDI1MTYxMTQxWhcNMTkx
MDI1MTYxMTQxWjAlMSMwIQYDVQQDExpvYXV0aC1wcm94eSBzZWNvbmQgdGVzdCBj
YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdTkEOJ+QpOHy0PqGDR
fu8NFyo7BJwAnI+P1G32UXMeecCwBgGJEyv6eHEFV6jH/U2K2H0hynaCFxRuIdTA
EeS4s4BAbKqFhQ62I9lF3HVuqRPOe5FYdUl80eQynME22fWQ6/sZdQds0sFqaJBz
R4KQQxVULT19Br/6zwQZZhC1NtzSwCqi4CoO2OM7ctUKRvtC87LNGWapz5I4eh0A
/q4XJaSObsBCAJD7OVMa1LM3sSINUnvvGoSBKTuJ8MRk/BQRAO/PwXxsa+2h+k+w
D6sLExrBgWzAAPQKRKF+nLYVhz9AKn4JBpZt9j4PvTKz1SDcJ5wVEzOfVmii7Ui3
EFcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAiy58XvhOka3drXv2bwl95FwNtodj
L2MmIdF0pp01O0ryREcC1kogamdOS/UHQs4okuCjwinR/UgU+cFGCDYHfeENtUTw
Ox2OikYD7bXUpNzbQ4QyF0+cKwAgxD4ai5xSV/NUvMkL1aE8tLyxGm6VkhhyvxU1
U9kvLha6KBWOCNd2fBJxgg8RAxFV3vR+xLdEtXnBAeTURrHM19gwMtd16y6gUZTZ
Xbl3Ix0t2+sqi0hpEF/iVFdCp5TXiicSnZCtePzCfHePAEfbh5hS0bq8Lbb9DZ6d
+2jX3AVuYhQPuutxla+vNp2XRcMTbzwXyi/Ig4nHKmPLFXsEbv+4tSwxyQ==
-----END CERTIFICATE-----
`
)

func makeTestCertFile(t *testing.T, pem, dir string) *os.File {
	file, err := ioutil.TempFile(dir, "test-certfile")
	assert.NoError(t, err)
	_, err = file.Write([]byte(pem))
	assert.NoError(t, err)
	return file
}

func TestGetCertPool_NoRoots(t *testing.T) {
	_, err := GetCertPool([]string(nil))
	assert.Error(t, err, "invalid empty list of Root CAs file paths")
}

func TestGetCertPool(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "certtest")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)
	certFile1 := makeTestCertFile(t, testCA1, tempDir)
	certFile2 := makeTestCertFile(t, testCA2, tempDir)

	certPool, err := GetCertPool([]string{certFile1.Name(), certFile2.Name()})
	assert.NoError(t, err)

	subj := certPool.Subjects()
	got := make([]string, 0)
	for i := range subj {
		var subject pkix.RDNSequence
		_, err := asn1.Unmarshal(subj[i], &subject)
		assert.NoError(t, err)
		got = append(got, subject.String())
	}

	expectedSubjects := []string{testCA1Subj, testCA2Subj}
	assert.Equal(t, expectedSubjects, got)
}

var _ = Describe("GetSecretValue", func() {
	var fileDir string
	const secretEnvKey = "SECRET_ENV_KEY"
	const secretEnvValue = "secret-env-value"
	var secretFileValue = []byte("secret-file-value")

	BeforeEach(func() {
		os.Setenv(secretEnvKey, secretEnvValue)

		var err error
		fileDir, err = ioutil.TempDir("", "oauth2-proxy-util-get-secret-value")
		Expect(err).ToNot(HaveOccurred())
		Expect(ioutil.WriteFile(path.Join(fileDir, "secret-file"), secretFileValue, 0600)).To(Succeed())
	})

	AfterEach(func() {
		os.Unsetenv(secretEnvKey)
		os.RemoveAll(fileDir)
	})

	It("returns the correct value from base64", func() {
		originalValue := []byte("secret-value-1")
		b64Value := base64.StdEncoding.EncodeToString((originalValue))

		// Once encoded, the originalValue could have a decoded length longer than
		// its actual length, ensure we trim this.
		// This assertion ensures we are testing the triming
		Expect(len(originalValue)).To(BeNumerically("<", base64.StdEncoding.DecodedLen(len(b64Value))))

		value, err := GetSecretValue(&options.SecretSource{
			Value: []byte(b64Value),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(value).To(Equal(originalValue))
	})

	It("returns the correct value from the environment", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromEnv: secretEnvKey,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(value).To(BeEquivalentTo(secretEnvValue))
	})

	It("returns the correct value from a file", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromFile: path.Join(fileDir, "secret-file"),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(value).To(Equal(secretFileValue))
	})

	It("when the file does not exist", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromFile: path.Join(fileDir, "not-exist"),
		})
		Expect(err).To(HaveOccurred())
		Expect(value).To(BeEmpty())
	})

	It("with no source set", func() {
		value, err := GetSecretValue(&options.SecretSource{})
		Expect(err).To(MatchError("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile"))
		Expect(value).To(BeEmpty())
	})

	It("with multiple sources set", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromEnv:  secretEnvKey,
			FromFile: path.Join(fileDir, "secret-file"),
		})
		Expect(err).To(MatchError("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile"))
		Expect(value).To(BeEmpty())
	})
})
