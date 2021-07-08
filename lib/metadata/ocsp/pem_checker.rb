require 'openssl'
require 'metadata/certificate/certificate_factory'
require 'metadata/certificate_repository'
require 'metadata/ocsp/client'
module Metadata
  module Ocsp
    class PemChecker
      def initialize(certificate_factory: Certificate::CertificateFactory.new, ocsp_checker: Ocsp::Client.new)
        @certificate_factory = certificate_factory
        @ocsp_checker = ocsp_checker
      end

      def check_pems(pems, ca_files, allow_self_signed)
        ca_certs = ca_files.map { |file| OpenSSL::X509::Certificate.new(File.read(file)) }
        issuer_repository = CertificateRepository.new(ca_certs)
        pems.each.with_object({}) do |pem, results|
          results[pem] = check_pem(pem, issuer_repository, allow_self_signed)
        end
      end

      def check_pem(pem, issuer_repository, allow_self_signed)
        cert = @certificate_factory.from_inline_pem(pem)
        if (allow_self_signed && cert.subject == cert.issuer) then
          Ocsp::Result.new(nil, nil)
        else
          chain = issuer_repository.find_chain(cert)
          store = chain.store
          issuer = chain.first
          raise "An issuer was not found in the ca certs for #{cert.subject.to_s}" if issuer.nil?
          @ocsp_checker.check([cert], issuer, store)[cert]
        end
      end
    end
  end
end
