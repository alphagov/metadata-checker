Feature: source certs are checked against published certs

  Background:
    Given the OCSP port is 54000

  Scenario: Certs don't match
    Given there are the following PKIs:
      | name         | cert_filename    |
      | TEST_PKI_ONE | test_pki_one.crt |
    Given the following certificates are defined in metadata:
      | entity_id | key_name  | pki          | status |
      | foo       | foo_key_1 | TEST_PKI_ONE | good   |
      | foo       | foo_key_2 | TEST_PKI_ONE | good   |
      | bar       | bar_key_1 | TEST_PKI_ONE | good   |
    And there is metadata at http://localhost:53010
    And there is an OCSP responder
    When I start the metadata checker with the arguments "-m http://localhost:53010 --cas tmp/aruba/ -p 2030 -e test"
    Then the metrics on port 2030 should contain exactly:
    """
    verify_metadata_sources_check{source_certs_not_in_published="/C=GB/ST=London/L=London/O=Cabinet Office/OU=GDS/CN=HUB Signing \(20210421104706\), /C=GB/ST=London/L=London/O=Cabinet Office/OU=GDS/CN=HUB Signing \(20210511131438\), /C=GB/ST=London/L=London/O=Cabinet Office/OU=GDS/CN=HUB Encryption \(20210421104706\), /C=NL/ST=Zuid-Holland/O=Digidentity B.V./OU=IT dept/CN=Digidentity AUTH SAML Signing-2020-12-10-PP, /C=NL/ST=Zuid-Holland/O=Digidentity B.V./OU=IT dept/CN=Digidentity AUTH SAML Signing-2020-12-10, /C=GB/ST=London/O=Post Office Ltd/OU=Managed Services/CN=Post Office production AUTH SAML Signing-2021-06-14",published_certs_not_in_source="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE, /DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE, /DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 9.0
    """