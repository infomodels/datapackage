package packer

import (
	"bytes"
	"io/ioutil"
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
