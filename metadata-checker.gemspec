# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'metadata/checker/version'

Gem::Specification.new do |spec|
  spec.name          = "metadata-checker"
  spec.version       = Metadata::Checker::VERSION
  spec.authors       = ["Christopher Holmes"]
  spec.email         = ["christopher.holmes@digital.cabinet-office.gov.uk"]
  spec.summary       = %q{A tool for verifying the status of certficates defined in SAML metadata}
  spec.description   = %q{A tool for verifying the status of certficates defined in SAML metadata}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "mixlib-cli", "~>2.0"
  spec.add_dependency "nokogiri", "~>1.6"
  spec.add_dependency "prometheus-client"
  spec.add_dependency "sinatra"
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.3"
  spec.add_development_dependency "rspec-expectations", "~> 3.3"
  spec.add_development_dependency "cucumber", "~> 1.3.20"
  spec.add_development_dependency "signer", "~> 1.4"
end
