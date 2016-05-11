package main

import (
	"os"
	"os/exec"
	"testing"
)

// Test packing of the test_data/data directory with the following command: `data-models packer -keyPath test_data/key.asc -model pedsnet -modelVersion 2.1.0 -site ORG -etl https://specificanddurable.com/etlv3 -out test_tmp/test.tar.gz.gpg test_data/data`.
func TestPack(t *testing.T) {

	// Make directory for test output files.
	os.Mkdir("test_tmp", 0755)

	// Build and run the test command, storing the STDOUT, STDERR and exit status.
	cmd := exec.Command("data-models-packer", "-keyPath", "test_data/key.asc", "-model", "pedsnet", "-modelVersion", "2.1.0", "-site", "ORG", "-etl", "https://specificanddurable.com/etlv3", "-out", "test_tmp/test.tar.gz.gpg", "test_data/data")
	outBytes, cmdErr := cmd.CombinedOutput()

	// Clean up test files.
	os.Remove("test_data/data/metadata.csv")
	os.RemoveAll("test_tmp")

	// Fail if the exit status is non-zero.
	if cmdErr != nil {
		t.Fatalf("error using binary to pack: %s\n%s", cmdErr, outBytes)
	}
}

// Test unpacking of the test_data/test.tar.gz.gpg package with the following command: `data-models-packer -keyPath test_data/key.asc -keyPassPath test_data/pass.txt -out test_tmp test_data/test.tar.gz.gpg`.
func TestUnpack(t *testing.T) {

	// Make directory for test output files.
	os.Mkdir("test_tmp", 0755)

	// Build and run the test command, storing the exit status.
	cmd := exec.Command("data-models-packer", "-keyPath", "test_data/key.asc", "-keyPassPath", "test_data/pass.txt", "-out", "test_tmp", "test_data/test.tar.gz.gpg")
	outBytes, cmdErr := cmd.CombinedOutput()

	// Clean up test files.
	os.RemoveAll("test_tmp")

	// Fail if the exit status is non-zero.
	if cmdErr != nil {
		t.Fatalf("error unpacking with binary: %s\n%s", cmdErr, outBytes)
	}
}

// Test verification of existing metadata file with the following command: `data-models-packer -verifyOnly test_data`.
func TestVerify(t *testing.T) {

	// Build the test command.
	cmd := exec.Command("data-models-packer", "-verifyOnly", "test_data")

	// Run the test command and fail if there is a non-zero exit status.
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("error verifying metadata with binary: %s\n%s", err, outBytes)
	}
}
