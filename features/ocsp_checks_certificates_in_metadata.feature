Feature: OCSP checks certificates in metadata

  In order to guarantee the health of the federation,
  As a service manager,
  I want to be alerted if our metadata contains revoked certificates

  Background:
    Given the OCSP port is 54000

  Scenario: Check healthy metadata
    Given there are the following PKIs:
      | name         | cert_filename    |
      | TEST_PKI_ONE | test_pki_one.crt |
    Given the following certificates are defined in metadata:
      | entity_id | key_name  | pki          | status     |
      | foo       | foo_key_1 | TEST_PKI_ONE | good       |
      | foo       | foo_key_2 | TEST_PKI_ONE | good       |
      | bar       | bar_key_1 | TEST_PKI_ONE | good       |
      | car       | car_key_3 | TEST_PKI_ONE | selfsigned |
    And there is metadata at http://localhost:53000
    And there is an OCSP responder
    When I start the metadata checker with the arguments "-m http://localhost:53000 --cas tmp/aruba/ -p 2020 --allow_self_signed"
    Then the metrics on port 2020 should contain exactly:
    """
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="2",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="3",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="bar",use="encryption",serial="4",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="car",use="encryption",serial="5",subject="/DC=org/DC=TEST/CN=SELF_SIGNED_CERT"} 1.0
    """

  Scenario: Check unhealthy metadata
    Given there are the following PKIs:
      | name         | cert_filename    |
      | TEST_PKI_ONE | test_pki_one.crt |
    Given the following certificates are defined in metadata:
      | entity_id | key_name  | pki          | status  |
      | foo       | foo_key_1 | TEST_PKI_ONE | good    |
      | foo       | foo_key_2 | TEST_PKI_ONE | good    |
      | bar       | bar_key_1 | TEST_PKI_ONE | revoked |
    Given there is metadata at http://localhost:53001
    And there is an OCSP responder
    When I start the metadata checker with the arguments "-m http://localhost:53001 --cas tmp/aruba/ -p 2021"
    Then the metrics on port 2021 should contain exactly:
    """
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="2",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="3",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="bar",use="encryption",serial="4",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 0.0
    """

  Scenario: Check metadata with more than one PKI
    Given there are the following PKIs:
      | name         | cert_filename    |
      | TEST_PKI_ONE | test_pki_one.crt |
      | TEST_PKI_TWO | test_pki_two.crt |
    Given the following certificates are defined in metadata:
      | entity_id | key_name  | pki          | status |
      | foo       | foo_key_1 | TEST_PKI_ONE | good   |
      | foo       | foo_key_2 | TEST_PKI_ONE | good   |
      | bar       | bar_key_1 | TEST_PKI_TWO | good   |
    And there is metadata at http://localhost:53002
    And there is an OCSP responder
    When I start the metadata checker with the arguments "-m http://localhost:53002 --cas tmp/aruba/ -p 2022"
    Then the metrics on port 2022 should contain exactly:
    """
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="2",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="3",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="bar",use="encryption",serial="2",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    """

  Scenario: Checks signed metadata
    Given there are the following PKIs:
      | name            | cert_filename       |
      | TEST_PKI_ONE    | test_pki_one.crt    |
      | SIGNING_PKI_ONE | signing_pki_one.crt |
    And the following certificates are defined in metadata:
      | entity_id | key_name  | pki          | status |
      | foo       | foo_key_1 | TEST_PKI_ONE | good   |
    And the metadata is signed by a certificate belonging to SIGNING_PKI_ONE
    And there is metadata at http://localhost:53003
    And there is an OCSP responder
    When I start the metadata checker with the arguments "-m http://localhost:53003 --cas tmp/aruba/ -p 2023"
    Then the metrics on port 2023 should contain exactly:
    """
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="2",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="metadata_signing_certificate",use="",serial="2",subject="/DC=org/DC=TEST/CN=SIGNED TEST CERTIFICATE"} 1.0
    """

  Scenario: Checks signed metadata with revoked signing certificate
    Given there are the following PKIs:
      | name            | cert_filename       |
      | TEST_PKI_ONE    | test_pki_one.crt    |
      | SIGNING_PKI_ONE | signing_pki_one.crt |
    And the following certificates are defined in metadata:
      | entity_id | key_name  | pki          | status |
      | foo       | foo_key_1 | TEST_PKI_ONE | good   |
    And the metadata is signed by a revoked certificate belonging to SIGNING_PKI_ONE
    And there is metadata at http://localhost:53004
    And there is an OCSP responder
    When I start the metadata checker with the arguments "-m http://localhost:53004 --cas tmp/aruba/ -p 2024"
    Then the metrics on port 2024 should contain exactly:
    """
    verify_metadata_certificate_ocsp_success{entity_id="foo",use="encryption",serial="2",subject="/DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE"} 1.0
    verify_metadata_certificate_ocsp_success{entity_id="metadata_signing_certificate",use="",serial="2",subject="/DC=org/DC=TEST/CN=SIGNED TEST CERTIFICATE"} 0.0
    """
