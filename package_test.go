package packer

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEncrypt tests the packer.Encrypt functionality.
func TestEncrypt(t *testing.T) {
	in := new(bytes.Buffer)

	encMsg, err := Encrypt(in, strings.NewReader(keyRing))
	if err != nil {
		t.Fatalf("packer tests: error adding encryption: %s", err)
	}

	_, err = encMsg.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("packer tests: error writing message: %s", err)
	}
	encMsg.Close()

	decMsg, err := Decrypt(in, strings.NewReader(keyRing), strings.NewReader(keyPass))
	if err != nil {
		t.Fatalf("packer test: error adding decryption: %s", err)
	}

	out, err := ioutil.ReadAll(decMsg)
	if err != nil {
		t.Fatalf("packer test: error decrypting message: %s", err)
	}

	if string(out) != testMsg {
		t.Fatalf("packer tests: round-trip message (%s) does not equal original (%s)", string(out), testMsg)
	}

}

const testMsg = `A test message`

// writeTempFile creates a temporary file containing specified string contents and returns the file name
func writeTempFile(t *testing.T, fileNamePrefix string, fileContents string) (name string) {
	file, err := ioutil.TempFile("", fileNamePrefix)
	if err != nil {
		t.Fatalf("packer tests: can't create temporary file: %v", err)
	}
	_, err = file.Write([]byte(fileContents))
	if err != nil {
		t.Fatalf("packer tests: can't write to temporary file: %v", err)
	}
	name = file.Name()
	file.Close()
	return
}

type TestEnv struct {
	DataDir, PackageDir, PackagePath, UnpackDataDir, PublicKeyFilePath, PrivateKeyFilePath, PrivateKeyPassphrasePath string
}

// NewTestEnv returns a test directory with files, a target packagePath, and an extra test directory
// This is paired with verifyTestFiles, which also cleans up the directories
// DON'T FORGET to remove any files created in RemoveTestFiles
func NewTestEnv(t *testing.T, gpg bool) *TestEnv {

	var (
		err error
		te  *TestEnv
	)

	te = new(TestEnv)

	te.DataDir, err = ioutil.TempDir("", "testdatadir")
	if err != nil {
		t.Fatalf("packer tests: can't create temporary directory")
	}

	content := []byte(testMsg)

	tmpfn := filepath.Join(te.DataDir, "datafile1.csv")
	if err = ioutil.WriteFile(tmpfn, content, 0666); err != nil {
		t.Fatalf("packer tests: error writing temp file: %v", err)
	}

	tmpfn = filepath.Join(te.DataDir, "datafile2.csv")
	if err = ioutil.WriteFile(tmpfn, content, 0666); err != nil {
		t.Fatalf("packer tests: error writing temp file: %v", err)
	}

	te.PackageDir, err = ioutil.TempDir("", "testpackagedir")
	if err != nil {
		t.Fatalf("packer tests: can't create temporary directory")
	}

	var ext = ""
	if gpg {
		ext = ".gpg"
	}
	te.PackagePath = filepath.Join(te.PackageDir, "test.tar.gz"+ext)

	te.UnpackDataDir, err = ioutil.TempDir("", "testunpackdatadir")
	if err != nil {
		t.Fatalf("packer tests: can't create temporary directory")
	}

	te.PublicKeyFilePath = writeTempFile(t, "test.public.key", testPublicKey)

	te.PrivateKeyFilePath = writeTempFile(t, "test.private.key", testPrivateKey)

	te.PrivateKeyPassphrasePath = writeTempFile(t, "test.private.key.passphrase", testPrivateKeyPassphrase)

	return te
}

func (te *TestEnv) VerifyUnpack(t *testing.T) {
	file1Path := filepath.Join(te.UnpackDataDir, "datafile1.csv")
	content, err := ioutil.ReadFile(file1Path)
	if err != nil || string(content) != testMsg {
		t.Fatalf("packer tests: datafile1.csv not successfully unpacked")
	}
	file2Path := filepath.Join(te.UnpackDataDir, "datafile2.csv")
	content, err = ioutil.ReadFile(file2Path)
	if err != nil || string(content) != testMsg {
		t.Fatalf("packer tests: datafile2.csv not successfully unpacked")
	}
}

func (te *TestEnv) RemoveTestFiles(t *testing.T) {
	os.RemoveAll(te.UnpackDataDir)
	os.RemoveAll(te.PackageDir)
	os.RemoveAll(te.DataDir)
	os.Remove(te.PublicKeyFilePath)
	os.Remove(te.PrivateKeyFilePath)
	os.Remove(te.PrivateKeyPassphrasePath)
}

func fatal(t *testing.T, msg string, err error, gpg bool, gpgLocalPublic bool) {
	t.Fatalf("%v%v w/gpg %v, gpgLocalPublic %v: %v", "packer tests: ", msg, gpg, gpgLocalPublic, err)
}

// testPacker tests Pack and Unpack given gpg-related parameters
func testPacker(t *testing.T, gpg bool, gpgLocalPublic bool) {

	var te = NewTestEnv(t, gpg)

	c := new(Config)
	c.DataDirPath = te.DataDir
	c.PackagePath = te.PackagePath
	if gpg {
		c.KeyPassPath = te.PrivateKeyPassphrasePath
		if gpgLocalPublic {
			c.KeyPath = te.PublicKeyFilePath
			// p.KeyPath will have to be changed prior to the Unpack operation to point to the private key; this is is a test-only hack
		} else {
			c.PublicKeyEmail = "testy@test.er"
		}
	}

	p, err := New(c)
	if err != nil {
		fatal(t, "error creating new package object", err, gpg, gpgLocalPublic)
	}

	if err := p.Pack(te.DataDir); err != nil {
		fatal(t, "error packing file", err, gpg, gpgLocalPublic)
	}

	if _, err := os.Stat(te.PackagePath); os.IsNotExist(err) {
		fatal(t, "package not produced", err, gpg, gpgLocalPublic)
	}

	if gpg {
		p.keyPath = te.PrivateKeyFilePath
	}
	if err := p.Unpack(te.UnpackDataDir); err != nil {
		fatal(t, "error unpacking file", err, gpg, gpgLocalPublic)
	}

	te.VerifyUnpack(t)
	te.RemoveTestFiles(t)
}

func TestPacker(t *testing.T) {

	testPacker(t, false, false) // test Pack and Unpack with no gpg
	testPacker(t, true, true)   // test Pack and Unpack with a local public gpg key file (KeyPath)
	testPacker(t, true, false)  // test Pack and Unpack with a lookup of a public key from a keyserver
}

// Email address used for test key pair below
const testKeyEmail = "testy@test.er"

// Public key for "Testy Tester"<testy@test.er>
const testPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFc19jwBCADIr4hG+vlnQ1sfnBLzI+T+KbFjFgCiiOSJ5jjcOYDTgfyE9SG1
JqxOD4qd8BWMqSPKHm8xPmnbBMfAN+Tw88hlzENIUcdYxRTZQWkNT/okM2K0MZ/l
LqfdGNJFE4fAadFBv1kVoEUUTo7uJdwU33tmuDH+Gsv6sAycPfk3uw/7B/Zmti9L
vxu7Zm8MV82YKl4CP/kXD685HVrQ1M5pvh6nYid9lqXR1IRFmbnB/cQaM2DsOLCg
QEu+sYK/O0Fez0P1tDIgL9lRWyamWUgDzY7mnI4cYHMvoxKRIFEUGQlaRI5oO58Q
mkOWrOnUg3ou0PmwtACjCPhCB7CMqgP381nNABEBAAG0M1Rlc3R5IFRlc3RlciAo
S2V5IHBhaXIgZm9yIHRlc3RpbmcpIDx0ZXN0eUB0ZXN0LmVyPokBOAQTAQIAIgUC
VzX2PAIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQkkovBoH8IYoXVQf+
PwLstmRq1DOhxG0MyFoh32SYwL4FSilSooKzI5C+A3QPZVWBKly2UM1hh3+MInQZ
aGFnfwnPbNVJcfrF4qCznCRx0sLk6gn7L1Lvi2XdRvdOqhX0Vz+siarpk5dBkjWN
tx2mow885jJVIFYDbOhYfot62UPc/Dtsk0Ksn5KWUavr4Qw+u3BEe3nkBgBRsTJZ
BDAY14dKIYXldMhOaoxAh09isEIVP/XSoofBJhm2jUyJToXF5U+jJzL6TdIN1M8+
AhuxbZn9OsDAsNMx6dd3HxqeymV/hN/YFWB2w2QLfDd4mIuw4ZfuF9Luk7Xa2Y87
b5UhnmnMkkmE+7rcIeaU6LkBDQRXNfY8AQgAvGxEXYoBuKpl4G8C+TFr4IZatiUL
tU8GgrM9RZ9k+RjVsC4DxWuzJc30JvqCfobkN135BGwmlg4o8X4ag5JhpKUdZ3pD
sk4D80j6VWBA3N2MdvspFKAfNdjkEQ3mwUx0QMEeSccsQwP/fjxGfgNelId9g/Hi
PHAB8Qhq9w8dG7qrFNTmLygdJpeUWcYIzmx2AJ18qG9qj61tYxU6JBX6jybC7s1U
+klaIu8JKUpYqZ79ppTrW4AMCPeq1ZOJavMrzAzhG6Ky93u7v7e05/zEgDuDkYi3
K0enTWpycJZD5Pf6/czYavD2bv/Z+I0FLe9X4B8h+7LH5j3O97rZnEJheQARAQAB
iQEfBBgBAgAJBQJXNfY8AhsMAAoJEJJKLwaB/CGKOWIH/Ra6QYRZzkrbccxBZCN6
wGzRIJqw/DD5CvG1KB5nMvUTSWwLslfvOAXolo87g6K6opv4vUf9TOeFvdZb4TAH
5V0VwMf7duBlxLEiFBZ8TbKpKpq4IUzP0dJUbCLKj/xpHNAp0eXmwPaUaU54DkTI
7wY3eLx3CS4PPuUNIksERgdQs+bstxXpxaoZW0ynNMapf5QLN1aNz10BMBaVWkGR
KaAyfCU7wcaqSfzSxoqu3fWJO/PvKojDA7OEuKhvMHHBNm1nGnMoUq95kMqzGKrb
Zn9spROT5uMoINY5aKG/5fl35NWBVnNohy+p189J6j4dEkHBehbBK1GcLVCYfjEO
A0I=
=Hrhy
-----END PGP PUBLIC KEY BLOCK-----
`

// Private key for "Testy Tester"<testy@test.er> (see below for passphrase)
const testPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

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
MQ4DQg==
=FViF
-----END PGP PRIVATE KEY BLOCK-----
`

// Passphrase for private key for "Testy Tester"<testy@test.er> (see above)
const testPrivateKeyPassphrase = "test"
