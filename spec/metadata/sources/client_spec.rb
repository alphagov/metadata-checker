require 'base64'
require 'ostruct'
require 'timecop'
require 'metadata/sources/client'


describe "Client" do
  let(:octokit_double) { instance_double(Octokit::Client) }
  subject(:client) { Metadata::Sources::Client.new("my_access_token", "prod") }

  before(:each) do
    expect(Octokit::Client)
      .to receive(:new)
            .with(access_token: "my_access_token")
            .and_return(octokit_double)

    allow(octokit_double)
      .to receive(:contents)
            .with(Metadata::Sources::METADATA_REPO, path: "sources/prod/hub.yml")
            .and_return(OpenStruct.new(content: File.open('fixtures/sources/test/hub.yml').read))

    allow(octokit_double)
      .to receive(:contents)
            .with(Metadata::Sources::METADATA_REPO, path: "sources/prod/idps")
            .and_return([{path: 'idp0.yml'}, {path: 'idp1.yml'}, {path: 'idp2.yml'}])

    3.times do |i|
      allow(octokit_double)
        .to receive(:contents)
              .with(Metadata::Sources::METADATA_REPO, path: "idp#{i}.yml")
              .and_return(OpenStruct.new(content: File.open("fixtures/sources/test/idps/idp#{i}.txt").read))
    end
  end

  describe "#get" do
    it "should return all hub and idp certs in a list" do
      expect(client.get).to eq(build_expected_certs)
    end

    it "should cache response from GitHub" do
      client.get
      expect(octokit_double).to have_received(:contents).exactly(5) # Initial calls to GitHub

      Timecop.travel(Time.now + Metadata::Sources::CACHE_VALID_DURATION - 5) # Travel to 5 seconds before the cache in invalid
      client.get
      expect(octokit_double).to have_received(:contents).exactly(5) # No more calls to GitHub

      Timecop.travel(Time.now + 10) # Travel a further 10 seconds, to 5 seconds after the cache is invalid
      client.get
      expect(octokit_double).to have_received(:contents).exactly(10) # Another round of calls to GitHub

      Timecop.return
    end
  end

  def build_expected_certs
    expected_certs = []
    base64_yaml_to_hash("fixtures/sources/test/hub.yml")["signing_certificates"].map { |cert| expected_certs << cert['x509'].gsub("\n", '') }
    expected_certs << base64_yaml_to_hash("fixtures/sources/test/hub.yml")["encryption_certificate"]["x509"].gsub("\n", '')
    3.times { |i| base64_yaml_to_hash("fixtures/sources/test/idps/idp#{i}.txt")["signing_certificates"].map { |cert| expected_certs << cert['x509'].gsub("\n", '')} }
    expected_certs
  end

  def base64_yaml_to_hash(file)
    YAML.load(Base64.decode64(File.open(file).read))
  end
end