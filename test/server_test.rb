require 'test_helper'

describe As2::Server do
  it 'accepts server_info as a config param'
  it 'uses global server config if server_info is nil'

  describe '#call' do
    describe 'when partner is given to constructor' do
      it 'returns an error if As2-From value does not match configured partner name'
    end

    describe 'when partner is not given to constructor' do
      it 'returns an error if As2-From value is not found in global partner config'
    end
  end

  describe '#send_mdn' do
    before do
      @partner = build_partner('ALICE', credentials: 'client')
      @server_info = build_server_info('BOB', credentials: 'server')

      @server = As2::Server.new(server_info: @server_info, partner: @partner)
    end

    # send_mdn(env, mic, mic_algorithm, failed = nil)
    it 'builds an MDN for a successful transmission' do
      env = {
        'HTTP_MESSAGE_ID' => '<message@server>',
        'HTTP_AS2_FROM' => 'ALICE'
      }
      _status, headers, body = @server.send_mdn(env, 'micmicmic', 'sha256')

      response = OpenSSL::PKCS7.read_smime body.first.strip
      assert_equal @server_info.certificate.serial, response.signers.first.serial

      response.verify [@server_info.certificate], OpenSSL::X509::Store.new, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN
      assert_nil response.error_string

      report = Mail.new(response.data)
      assert_equal 2, report.parts.size

      plain_text = report.parts[0]
      notification = report.parts[1]

      expected_plain_text = "The AS2 message has been received successfully"
      expected_notification = <<~EOF
        Reporting-UA: BOB
        Original-Recipient: rfc822; BOB
        Final-Recipient: rfc822; BOB
        Original-Message-ID: <message@server>
        Disposition: automatic-action/MDN-sent-automatically; processed
        Received-Content-MIC: micmicmic, sha256
      EOF

      assert_equal 'BOB', headers['AS2-From']
      assert_equal 'ALICE', headers['AS2-To']
      assert_equal expected_plain_text.strip, plain_text.body.to_s.strip
      assert_equal expected_notification.strip, notification.body.to_s.strip
    end

    it 'builds an MDN for a failed transmission' do
      env = {
        'HTTP_MESSAGE_ID' => '<message@server>',
        'HTTP_AS2_FROM' => 'ALICE'
      }
      _status, headers, body = @server.send_mdn(env, 'micmicmic', 'sha256', 'error message')

      # TODO: this fails when MIME headers are not present in body.
      # we can instead extract them from the HTTP Content-Type header.
      response = OpenSSL::PKCS7.read_smime body.first.strip
      assert_equal @server_info.certificate.serial, response.signers.first.serial

      response.verify [@server_info.certificate], OpenSSL::X509::Store.new, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN
      assert_nil response.error_string

      report = Mail.new(response.data)
      assert_equal 2, report.parts.size

      plain_text = report.parts[0]
      notification = report.parts[1]

      expected_plain_text = <<~EOF
        There was an error with the AS2 transmission.

        error message
      EOF

      expected_notification = <<~EOF
        Reporting-UA: BOB
        Original-Recipient: rfc822; BOB
        Final-Recipient: rfc822; BOB
        Original-Message-ID: <message@server>
        Disposition: automatic-action/MDN-sent-automatically; failed
        Failure: error message
        Received-Content-MIC: micmicmic, sha256
      EOF

      assert_equal 'BOB', headers['AS2-From']
      assert_equal 'ALICE', headers['AS2-To']
      assert_equal expected_plain_text.strip, plain_text.body.to_s.strip
      assert_equal expected_notification.strip, notification.body.to_s.strip
    end
  end
end
