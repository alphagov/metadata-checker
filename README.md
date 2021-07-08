# Metadata Exporter

A prometheus exporter that exports metrics about SAML metadata.

## Installation

Install it yourself as:

    $ gem install metadata-exporter

## Packaging

To generate a package for metadata-exporter:

    docker build ./

Then upload the image to the desired repository.

## Usage

To run the prometheus exporter:

    bundle exec bin/prometheus-metadata-exporter -m METADATA_URL --cas DIRECTORY_OF_CA_CERTIFICATE_FILES [--allow_self_signed]
    
The directory of DIRECTORY_OF_CA_CERTS should contain the certificate chains for the metadata signing cert as well as any signing and encryption certs within the SAML.

Self-signed certs do not need a chain, but you should provide the optional `--allow_self_signed` parameter.

The following metrics are exported:

    - `verify_metadata_expiry`: when the SAML metadata signature expires
    - `verify_metadata_certificate_expiry`: when the given certificate expires
    - `verify_metadata_certificate_ocsp_success`: whether the given certificate passes OCSP

## Contributing

1. Fork it ( https://github.com/[my-github-username]/metadata-exporter/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
