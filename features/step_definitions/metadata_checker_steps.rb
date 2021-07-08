require 'net/http'

metadata_server = nil

Given(/^there is metadata at http:\/\/localhost:(\d+)$/) do |port|
  raise "@metadata must be set!" if @metadata.nil?
  metadata_server = MetadataServer.new(port, @metadata)
  metadata_server.start!
end

Given(/^the OCSP port is (\d+)$/) do |port|
  @ocsp_port = port
end

Given(/^there is an OCSP responder$/) do
  raise "@ocsp_port must be set!" if @ocsp_port.nil?
  OCSPResponder.start!(PKIS.values, @ocsp_port)
end

Given(/^there are the following PKIs:$/) do |table|
  raise "@ocsp_port must be set!" if @ocsp_port.nil?
  ocsp_host = "http://localhost:#@ocsp_port"
  table.hashes.each do |pki|
    new_pki = PKI.new(pki["name"], ocsp_host)
    PKIS[pki["name"]] = new_pki
    write_file(pki["cert_filename"], new_pki.root_ca)
  end
end

Given(/^the following certificates are defined in metadata:$/) do |table|
  metadata_entries = Hash.new do |hash, key|
    hash[key] = []
  end
  table.hashes.each do |ent|
    pki = PKIS.fetch(ent["pki"])

    key = nil
    case ent["status"]
    when "expired"
      cert = pki.generate_cert_with_expiry(Time.now-(60*60*24*15), "EXPIRED CERT")
    when "selfsigned"
      pair = pki.generate_cert_and_key(Time.now+(60*60*24*365), "SELF_SIGNED_CERT")
      cert = pair[0]
      key = pair[1]
    else
      cert = pki.generate_cert
    end

    signed_cert = pki.sign(cert, key)

    if ent["status"] == "revoked"
      pki.revoke(signed_cert)
    end

    cert_value = pki.inline_pem(signed_cert)
    metadata_entries[ent.fetch("entity_id")] << { :key_name => ent['key_name'], :cert_value => cert_value}
  end
  @metadata = build_metadata(metadata_entries)
end

Given(/^the metadata is signed by a (revoked )?certificate belonging to (\w+)$/) do |revoked, pki_name|
  pki = PKIS.fetch(pki_name)
  signing_public_certificate, signing_private_key = *pki.generate_signed_cert_and_private_key
  @metadata = sign_metadata(@metadata, signing_private_key, signing_public_certificate)
  if revoked
    pki.revoke(signing_public_certificate)
  end
end

Then(/^the metrics on port (\d+) should contain certificate expires exactly:$/) do |port, table|
  uri = URI("http://localhost:#{port}/metrics")
  begin
    Net::HTTP.start(uri.host, uri.port) do |http|
      response = http.request Net::HTTP::Get.new uri
      expect(response.code).to eq("200")

      body = response.body

      table.hashes.each do |ent|
        regex_str = "verify_metadata_certificate_expiry{entity_id=\"#{ent["entity_id"]}\",use=\"encryption\",serial=\"#{ent["serial"]}\",subject=\"#{ent["subject"]}\"} (\\d+).0"

        match = body.match(Regexp.new(regex_str))

        if match.nil?
          fail("Couldn't match on expected metric")
        else
          timestamp = match.captures[0].to_i / 1000
          diff = Time.now.to_i - (timestamp - 31536000)
          if ent["status"] == "good"
            expect(diff).to be_between(0, 10)
          else
            expect(diff).to be > 10
          end
        end
      end
    end
  rescue
    fail
  end
end

Then(/^the metrics on port (\d+) should contain exactly:$/) do |port, expected_string|
    uri = URI("http://localhost:#{port}/metrics")
    begin
        Net::HTTP.start(uri.host, uri.port) do |http|
            response = http.request Net::HTTP::Get.new uri
            expect(response.code).to eq("200")

            regex_result = Regexp.new(expected_string.chomp)
            expect(response.body.chomp).to match(regex_result)
        end
    rescue
        fail
    end
end

metadata_process = nil

When(/^I start the metadata checker with the arguments "(.*?)"$/) do |process_arguments|
   metadata_process = spawn("bin/prometheus-metadata-exporter #{process_arguments}")
  sleep(2) #wait for the server to come up
end

After do
  Process.kill("SIGKILL", metadata_process) unless metadata_process.nil?
  metadata_server.stop! unless metadata_server.nil?
end

# http://fractio.nl/2010/09/14/testing-daemons-with-cucumber/
When /^I start the prometheus client on port (\d+) with metadata on port (\d+) with ca (.*)$/ do |pcport, mport, ca_file|
  @root = Pathname.new(File.dirname(__FILE__)).parent.parent.expand_path
  command = "#{@root.join('bin')}/prometheus-metadata-exporter -p #{pcport} -m http://localhost:#{mport} --cas tmp/aruba/"

  @pipe = IO.popen(command, "r")
  sleep 2 # so the daemon has a chance to boot

  # clean up the daemon when the tests finish
  at_exit do
    Process.kill("KILL", @pipe.pid)
  end
end
