Feature: expiry of certificates in metadata is checked

  In order to gurantee the health of the federation,
  As a service manager,
  I want to be alerted if our metadata contains certificates that will expire soon

  Background:
    Given the OCSP port is 54000

  Scenario: Check healthy metadata
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
    Then the metrics on port 2030 should contain certificate expires exactly:
      | entity_id | serial | subject                                       | status |
      | foo       | 2      | /DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE | good   |
      | foo       | 3      | /DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE | good   |
      | bar       | 4      | /DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE | good   |

  Scenario: Check metadata with expired certificate
    Given there are the following PKIs:
      | name         | cert_filename    |
      | TEST_PKI_ONE | test_pki_one.crt |
    Given the following certificates are defined in metadata:
      | entity_id | key_name  | pki          | status  |
      | foo       | foo_key_1 | TEST_PKI_ONE | good    |
      | foo       | foo_key_2 | TEST_PKI_ONE | good    |
      | bar       | bar_key_1 | TEST_PKI_ONE | expired |
    Given there is metadata at http://localhost:53013
    And there is an OCSP responder
    When I start the metadata checker with the arguments "-m http://localhost:53013 --cas tmp/aruba/ -p 2033 -e test"
    Then the metrics on port 2033 should contain certificate expires exactly:
      | entity_id | serial | subject                                       | status  |
      | foo       | 2      | /DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE | good    |
      | foo       | 3      | /DC=org/DC=TEST/CN=GENERATED TEST CERTIFICATE | good    |
      | bar       | 4      | /DC=org/DC=TEST/CN=EXPIRED CERT               | expired |

