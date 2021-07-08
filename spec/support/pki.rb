require 'openssl'
require 'uri'
require 'base64'
require 'certificate_helper'
class PKI
  include CertificateHelper
  attr_reader :root_ca, :root_key, :ocsp_host
  def initialize(cn = "TEST CA", ocsp_host = "http://localhost:4568")
    @root_ca = generate_root_certificate(cn)
    @revoked_certificates = {}
    @ocsp_host = URI(ocsp_host)
  end

  def generate_root_certificate(cn)
    @root_key = OpenSSL::PKey::RSA.new 2048 # the CA's public/private key
    root_ca = OpenSSL::X509::Certificate.new
    root_ca.version = 2 # cf. RFC 5280 - to make it a "v3" certificate
    root_ca.serial = take_next_serial
    root_ca.subject = OpenSSL::X509::Name.parse "/DC=org/DC=TEST/CN=#{cn}"
    root_ca.issuer = root_ca.subject # root CA's are "self-signed"
    root_ca.public_key = @root_key.public_key
    root_ca.not_before = Time.now
    root_ca.not_after = root_ca.not_before + 2 * 365 * 24 * 60 * 60 # 2 years validity
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = root_ca
    ef.issuer_certificate = root_ca
    root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
    root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    root_ca.sign(@root_key, OpenSSL::Digest::SHA256.new)
  end

  def take_next_serial
    @serial_count ||= 0
    @serial_count += 1
  end

  def sign(cert, key = nil)
    selfsign = !key.nil?
    cert.issuer = selfsign ? cert.subject : @root_ca.subject
    cert.serial = take_next_serial
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = selfsign ? cert : root_ca
    cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    unless selfsign
      ocsp_extension = ef.create_extension("authorityInfoAccess","OCSP;URI:#{@ocsp_host.to_s}")
      cert.add_extension(ocsp_extension)
    end
    cert.sign(selfsign ? key : @root_key, OpenSSL::Digest::SHA256.new)
    cert
  end

  def generate_signed_cert(cn = "SIGNED TEST CERTIFICATE")
    sign(generate_cert(cn))
  end

  def generate_signed_cert_and_private_key(cn = "SIGNED TEST CERTIFICATE")
    cert, key = *generate_cert_and_key((Time.now+60*60*24*365), cn)
    [sign(cert), key]
  end

  def revoke(certificate)
    @revoked_certificates[certificate.serial.to_i] = { time: Time.now, reason: 0 }
  end

  def revocation_data(serial)
    @revoked_certificates[serial.to_i]
  end
end

