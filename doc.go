/*
Package packer is a packer and unpacker of CSV files adhering to the Data
Models (https://github.com/chop-dbhi/data-models) specification. The source
code is hosted on GitHub (https://github.com/chop-dbhi/data-models-packer).

Install

Download the latest binary from the releases page
(https://github.com/chop-dbhi/data-models-packer/releases) for your
architecture: Windows, Linux, or OS X. The following examples assume the binary
has been placed on your 'PATH' with the name 'data-models-packer'.

Functionality

The data models packer has two operating modes depending on the input.

If the final argument is the path to a directory, it will be packed by:

    - Generating a 'metadata.csv' file, unless one already exists.
        - For 'metadata.csv' generation, any information not specified in
        command line arguments will be collected interactively.
        - If a 'metadata.csv' already exists, its contents will be checked
        for accuracy.
    - Compressing the directory recursively.
    - Encrypting the output into the specified file or onto STDIN.

If the final argument is the path to a file, it will be unpacked by:

    - Decrypting the file if it has a '.gpg' extension.
    - Decompressing the file if it has a recognized compression extension.
    - Verifying the packages integrity using the 'metadata.csv' file.

If the final argument is omitted, **STDIN** will be **unpacked** as above.

Usage

The data models packer binary can minimally be called with simply a file to
unpack or a directory to pack.

However, the user will usually want to specify an output directory or file, at
least. Some simple but common examples can be seen in the section below and the
full argument specification is in the next section.

Examples

Pack a directory into a file.

    data-models-packer -out test.tar.gz.gpg data/test

Verify an existing metadata.csv file only.

    data-models-packer -verifyMetadata data/test

Unpack an unencrypted package into a directory.

    data-models-packer -out data/test test.tar.gz

Unpack an encrypted data archive (with the passphrase in a file).

    data-models-packer -keyPath key.asc -keyPassPath pass.txt test.tar.gz.gpg

Unpack an encrypted data archive (with the passphrase in an env var).

    PACKER_KEYPASS=foobar data-models-packer -keyPath key.asc test.tar.gz.gpg

Arguments

    -comp string
          The compression method to be used: '.zip', '.tar.gz', '.tar.gzip',
          '.tar.bz2', or '.tar.bzip2'. If omitted, the '.tar.gz' method will be
          used for packing and the file extension will be used to infer a
          method for unpacking or the STDIN stream is assumed to be
          uncompressed.
    -dataVersion string
          The specific version of the data in the package.
    -etl string
          The URL of the ETL code used to generate data. Should be specific to the
          version of code used and remain that way over time.
    -keyPassPath string
          The filepath to the file containing the passphrase needed to access
          the private key. If omitted, the 'PACKER_KEYPASS' environment
          variable will be used, if that is unset, the private key is assumed
          to be unprotected.
    -keyPath string
          The filepath to the public key to use for encrypting packaged data or
          to the private key to use for unpacking encrypted data. If omitted,
          the data is assumed to be unencrypted.
    -model string
          The data model to operate against.
    -modelVersion string
          The specific version of the model to operate against. Defaults to the
          latest version of the model.
    -out string
          The directory or filename that should be written to. If omitted, data
          will be unpacked into the current directory or packed onto STDOUT.
    -service string
          The URL of the data models service to use for fetching schema
          information.
    -site string
          The site that generated the data.
    -verifyOnly
          Only verify an existing 'metadata.csv' file in the given data
          directory. Do not package the directory.

Developers

Install the dependencies.

    make install

Build the binary.

    make build

Run tests.

    make test
*/
package packer
