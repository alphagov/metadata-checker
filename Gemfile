source 'https://rubygems.org'

gem 'octokit', '4.21.0'

# Specify your gem's dependencies in metadata-ocsp-checker.gemspec
gemspec

group :test do
  gem 'r509-ocsp-responder', git: 'https://github.com/r509/r509-ocsp-responder.git', ref: 'dce3812bea227d2c48614822e6666ab5d93d2fb1'
  gem 'aruba'
  gem 'timecop'
end

group :ci do
  gem 'ci_reporter'
  gem 'ci_reporter_rspec'
  gem 'ci_reporter_cucumber'
end
