require 'metadata/saml/parser'
require 'metadata_helper'
require 'pki'

RSpec.configure do |config|
  config.include MetadataHelper
end

module Metadata
  module SAML
    describe Parser do
      context "#signing_certificate" do
        it "returns the signing_certificate as hash of pem string to identity" do
          pki = PKI.new
          public_cert, private_key = *pki.generate_signed_cert_and_private_key
          metadata = build_metadata({})
          signed_metadata = sign_metadata(metadata, private_key, public_cert)
          doc = Nokogiri::XML(signed_metadata)
          hash = Parser.new.signing_certificate(doc)
          expect(hash).to eql({ Base64.strict_encode64(public_cert.to_der) => [Entity.new("metadata_signing_certificate")]})
        end
      end

      context "#certificate_identities " do
        it "returns a hash of certificates to identities of their owners" do
          foo_cert_1 = "FOOCERT1"
          foo_cert_2 = "FOOCERT2"
          bar_cert_1 = "BARCERT1"

          metadata_entries = {
            "foo_id" => [
              {:key_name => "foo_1", :cert_value => foo_cert_1}, 
              {:key_name => "foo_2", :cert_value => foo_cert_2}, 
            ],
            "bar_id" => [
              {:key_name => "bar_1", :cert_value => bar_cert_1}, 
            ]
          }

          metadata = build_metadata(metadata_entries)
          doc = Nokogiri::XML(metadata)

          certificate_identities = Parser.new.certificate_identities(doc)
          expected_identities = {
            foo_cert_1 => [Entity.new("foo_id", "foo_1", "encryption")],
            foo_cert_2 => [Entity.new("foo_id", "foo_2", "encryption")],
            bar_cert_1 => [Entity.new("bar_id", "bar_1", "encryption")]
          }
          expect(certificate_identities).to eq expected_identities
        end
        it "allows for certificate to have many owners" do
          foo_cert_1 = "FOOCERT1"

          metadata_entries = {
            "foo_id" => [
              {:key_name => "foo_1", :cert_value => foo_cert_1}, 
              {:key_name => "foo_2", :cert_value => foo_cert_1}, 
            ],
            "bar_id" => [
              {:key_name => "bar_1", :cert_value => foo_cert_1}, 
            ]
          }

          metadata = build_metadata(metadata_entries)
          doc = Nokogiri::XML(metadata)

          certificate_identities = Parser.new.certificate_identities(doc)
          expected_identities = {
            foo_cert_1 => [
              Entity.new("foo_id", "foo_1", "encryption"),
              Entity.new("foo_id", "foo_2", "encryption"),
              Entity.new("bar_id", "bar_1", "encryption")
            ]
          }
          expect(certificate_identities).to eq expected_identities
        end
      end

      context '#all_entity_certificates' do
        it 'returns all the certificates' do
          foo_cert_1 = "FOOCERT1"
          foo_cert_2 = "FOOCERT2"
          bar_cert_1 = "BARCERT1"

          metadata_entries = {
            "foo_id" => [
              {:key_name => "foo_1", :cert_value => foo_cert_1},
              {:key_name => "foo_2", :cert_value => foo_cert_2},
            ],
            "bar_id" => [
              {:key_name => "bar_1", :cert_value => bar_cert_1},
            ]
          }

          metadata = build_metadata(metadata_entries)
          doc = Nokogiri::XML(metadata)

          certs = Parser.new.all_entity_certificates(doc)
          expect(certs).to eq([foo_cert_1, foo_cert_2, bar_cert_1])
        end
      end
    end
  end
end
