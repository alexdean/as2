require 'test_helper'

# TODO: get rid of instance variables in client integration test scenarios.
#
#   1. convert instance variables to method parameters in this method
#      (extend what's done here for http_response_status)
#   2. return a hash with data needed by individual tests
def setup_integration_scenario(
  http_response_status: nil,
  outbound_format: 'v0'
)
  # scenario: Alice is sending a message to Bob.
  @alice_partner = build_partner('ALICE', credentials: 'client', outbound_format: outbound_format)
  @alice_server_info = build_server_info('ALICE', credentials: 'client')

  @bob_partner = build_partner('BOB', credentials: 'server', outbound_format: outbound_format)
  @bob_server_info = build_server_info('BOB', credentials: 'server')

  @alice_client = As2::Client.new(@bob_partner, server_info: @alice_server_info)
  # individual tests will provide a different @bob_server if they want to assert on its behavior
  @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner)

  WebMock.stub_request(:post, @bob_partner.url).to_return do |request|
    # do all the HTTP things that rack would do during a real request
    headers = request.headers.transform_keys {|k| "HTTP_#{k.upcase}".gsub('-', '_') }
    env = Rack::MockRequest.env_for(request.uri.path, headers.merge(input: request.body))

    # then hand off the content to @bob_server (which must be defined by the actual tests below)
    status, headers, body = @bob_server.call(env)
    {
      status: http_response_status || status,
      headers: headers,
      body: body.first
    }
  end
end

describe As2::Client do
  after do
    As2.reset_config!
  end

  describe '.valid_outbound_formats' do
    it 'describes which formats are valid' do
      assert_equal(['v0', 'v1'], As2::Client.valid_outbound_formats)
    end
  end

  it 'accepts partner info as a config param' do
    partner = build_partner('ALICE', credentials: 'client')

    client = As2::Client.new(partner)

    assert_equal partner, client.partner
  end

  it 'accepts partner info as a string, which is searched in global config' do
    As2.configure do |conf|
      conf.name = 'BOB'
      conf.certificate = public_key("test/certificates/server.crt")
      conf.url = 'https://test.com'
      conf.domain = 'test.com'

      conf.add_partner do |partner|
        partner.name = 'ALICE'
        partner.url = 'http://localhost:3000'
        partner.certificate = public_key("test/certificates/client.crt")
      end
    end

    client = As2::Client.new('ALICE')

    assert_equal client.partner, As2::Config.partners['ALICE']
  end

  it 'accepts server_info as a config param' do
    partner = build_partner('ALICE', credentials: 'client')
    server_info = build_server_info('BOB', credentials: 'server')

    client = As2::Client.new(partner, server_info: server_info)

    assert_equal server_info, client.server_info
  end

  it 'defaults to using global server_info if server_info is nil' do
    As2.configure do |conf|
      conf.name = 'BOB'
      conf.certificate = public_key("test/certificates/server.crt")
      conf.url = 'https://test.com'
      conf.domain = 'test.com'
    end

    partner = build_partner('ALICE', credentials: 'client')

    client = As2::Client.new(partner)

    assert_equal As2::Config.server_info, client.server_info
  end

  describe '#evaluate_mdn' do
    before do
      partner = build_partner('CLIENT', credentials: 'client')
      server_info = build_server_info('SERVER', credentials: 'server')
      @client = As2::Client.new(partner, server_info: server_info)

      # capture this out-of-band when i wrote the test.
      # NOTE: this is the v0 outbound format
      @document_payload =  "Content-Type: text/plain\r\n"
      @document_payload << "Content-Transfer-Encoding: base64\r\n"
      @document_payload << "Content-Disposition: attachment; filename=test.txt\r\n"
      @document_payload << "\r\n"
      @document_payload << Base64.strict_encode64('This is a test message.')
    end

    # can use this to create new YAML files for responses from live servers
    #
    # client = As2::Client.new('OPENAS2')
    # as2_result = client.send_file('test.txt', content: 'This is a test message.', content_type: 'text/plain')
    # File.open('test/fixtures/binary_mdn.yml', 'wb') { |fp| fp.write(serialize_mdn(result)) }

    # def serialize_mdn(as2_result)
    #   # if set, response will be a Net::HTTPResponse
    #   response = as2_result&.response

    #   # headers are going to have string keys. so using string keys here also.
    #   # so we don't have to remember which level in the payload has which kind of key.
    #   YAML.dump({
    #     'code' => response&.code,
    #     'headers' => response&.each_capitalized&.to_h || {},
    #     'body' => response&.body
    #   })
    # end

    it 'handles a signed mdn' do
      mdn_data = YAML.load(File.read('test/fixtures/signed_mdn.yml'))

      result = @client.evaluate_mdn(
                 mdn_body: mdn_data['body'],
                 mdn_content_type: mdn_data['headers']['Content-Type'],
                 original_message_id: '<SERVER-20220318-222842-b176dc1a-44fd-4f9c-ac61-813fbb0f579a@server.test-ruby-as2.com>',
                 original_body: @document_payload
               )

      assert result[:mic_matched]
      assert result[:mid_matched]
      assert_nil result[:signature_verification_error]
      assert_equal 'automatic-action/MDN-sent-automatically; processed', result[:disposition]

      expected_body = "The AS2 message has been received. " \
        "Thank you for exchanging AS2 messages with mendelson opensource AS2.\n" \
        "Please download your free copy of mendelson opensource AS2 today at http://opensource.mendelson-e-c.com"

      assert_equal expected_body, result[:plain_text_body]
    end

    # TODO: this test MDN is unsigned due to a configuration error. ("Sender AS2 id SERVER is unknown.")
    # we should also have a test that a server which is correctly configured but which sends an unsigned MDN,
    # can be properly understood.
    #
    # basically: `assert_nil result[:mic_matched]` should not be asserted for non-error cases.
    it 'handles an unsigned mdn' do
      mdn_data = YAML.load(File.read('test/fixtures/unsigned_mdn.yml'))

      result = @client.evaluate_mdn(
                 mdn_body: mdn_data['body'],
                 mdn_content_type: mdn_data['headers']['Content-Type'],
                 original_message_id: '<SERVER-20220318-222924-774c8348-6372-4f7e-b84f-d7fced6daf58@server.test-ruby-as2.com>',
                 original_body: @document_payload
               )

      assert_nil result[:mic_matched]
      assert result[:mid_matched]
      assert_equal :not_checked, result[:signature_verification_error]
      assert_equal 'automatic-action/MDN-sent-automatically; processed/error: unknown-trading-partner', result[:disposition]

      expected_body = "Thank you for exchanging AS2 messages with mendelson opensource AS2.\n" \
        "Please download your free copy of mendelson opensource AS2 + today at http://opensource.mendelson-e-c.com.\n\n" \
        "An error occured during the AS2 message processing: Sender AS2 id SERVER is unknown."

      assert_equal expected_body, result[:plain_text_body]
    end

    it "parses an MDN with a lower-case 'disposition:' header" # eg: "disposition: automatic-action/MDN-sent-automatically; processed"
    it "parses an MDN with extended 'Content-Type:'" # eg: 'Content-Type: text/plain; charset="UTF-8"'
    it "parses an MDN which is missing 'Received-Content-MIC:'"

    it "parses an MDN which uses 'Content-Transfer-Encoding: binary'" do
      mdn_data = YAML.load(File.read('test/fixtures/binary_mdn.yml'))

      result = @client.evaluate_mdn(
                 mdn_body: mdn_data['body'],
                 mdn_content_type: mdn_data['headers']['Content-Type'],
                 original_message_id: '<RUBYAS2-20230224-133137-92068859-ef3c-4313-b164-a1b09851448e@localhost>',
                 original_body: @document_payload
               )

      assert result[:mic_matched]
      assert result[:mid_matched]
      assert_nil result[:signature_verification_error]
      assert_equal 'automatic-action/MDN-sent-automatically; processed', result[:disposition]

      expected_body = "The message sent to Recipient OPENAS2 on Fri, 24 Feb 2023 13:31:37 -0600 " \
        "with Subject AS2 Transaction has been received, the EDI Interchange was successfully decrypted " \
        "and it's integrity was verified. In addition, the sender of the message, Sender RUBYAS2 at Location " \
        "/172.17.0.1 was authenticated as the originator of the message. There is no guarantee however " \
        "that the EDI Interchange was syntactically correct, or was received by the EDI application/translator."

      assert_equal expected_body, result[:plain_text_body]
    end

    describe 'when partner uses separate encryption and signing certificates' do
      it 'verifies signature using partner signing_certificate' do
        server_info = build_server_info('SERVER', credentials: 'server')
        # NOTE: this MDN was signed with the private key of test/certificates/client.crt
        mdn_data = YAML.load(File.read('test/fixtures/signed_mdn.yml'))
        mdn_evaluation_params = {
          mdn_body: mdn_data['body'],
          mdn_content_type: mdn_data['headers']['Content-Type'],
          original_message_id: '<SERVER-20220318-222842-b176dc1a-44fd-4f9c-ac61-813fbb0f579a@server.test-ruby-as2.com>',
          original_body: @document_payload
        }

        correct_partner_config = As2::Config::Partner.new
        correct_partner_config.signing_certificate = public_key("test/certificates/client.crt")
        client = As2::Client.new(correct_partner_config, server_info: server_info)
        result = client.evaluate_mdn(**mdn_evaluation_params)
        assert_nil result[:signature_verification_error]

        incorrect_partner_config = As2::Config::Partner.new
        incorrect_partner_config.signing_certificate = public_key("test/certificates/server.crt")
        client = As2::Client.new(incorrect_partner_config, server_info: server_info)
        result = client.evaluate_mdn(**mdn_evaluation_params)
        assert_equal "signer certificate not found", result[:signature_verification_error]
      end
    end
  end

  describe '#send_file' do
    # these may contain spaces, which must be quoted.
    # https://datatracker.ietf.org/doc/html/rfc4130#section-6.2
    it "quotes As2-From and As2-To headers when they contain spaces" do
      alice_partner = build_partner('A L I C E', credentials: 'client')
      alice_server_info = build_server_info('A L I C E', credentials: 'client')
      bob_partner = build_partner('B O B', credentials: 'server')
      bob_server_info = build_server_info('B O B', credentials: 'server')

      alice_client = As2::Client.new(bob_partner, server_info: alice_server_info)

      WebMock.stub_request(:post, bob_partner.url).to_return do |request|
        assert_equal '"A L I C E"', request.headers['As2-From']
        assert_equal '"B O B"', request.headers['As2-To']
      end

      alice_client.send_file('data.txt', content: File.read('test/fixtures/message.txt'))
    end

    it "does not quotes As2-From and As2-To headers when they contain no spaces" do
      alice_partner = build_partner('ALICE', credentials: 'client')
      alice_server_info = build_server_info('ALICE', credentials: 'client')
      bob_partner = build_partner('BOB', credentials: 'server')
      bob_server_info = build_server_info('BOB', credentials: 'server')

      alice_client = As2::Client.new(bob_partner, server_info: alice_server_info)

      WebMock.stub_request(:post, bob_partner.url).to_return do |request|
        assert_equal 'ALICE', request.headers['As2-From']
        assert_equal 'BOB', request.headers['As2-To']
      end

      alice_client.send_file('data.txt', content: File.read('test/fixtures/message.txt'))
    end

    it 'considers a 2xx response code to be successful' do
      setup_integration_scenario(http_response_status: '202')

      @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner)

      result = @alice_client.send_file('data.txt', content: File.read('test/fixtures/message.txt'))

      assert_equal As2::Client::Result, result.class
      assert result.success
    end

    it 'considers a 5xx response code to be an error' do
      setup_integration_scenario(http_response_status: '500')

      @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner)

      result = @alice_client.send_file('data.txt', content: File.read('test/fixtures/message.txt'))

      assert_equal As2::Client::Result, result.class
      assert_equal Net::HTTPServerError, result.response.code_type
      assert !result.success
    end

    it 'captures and returns any exception raised while processing MDN response' do
      setup_integration_scenario

      expected_error_message = "error parsing attachment"
      mail_replacment = ->(*args) { raise expected_error_message }

      Mail.stub(:new, mail_replacment) do
        result = @alice_client.send_file('file_name.txt', content: 'file content')

        assert_equal RuntimeError, result.exception.class
        assert_equal expected_error_message, result.exception.message
        assert_nil result.success
      end
    end

    describe 'when partner uses separate encryption and signing certificates' do
      it "encrypts message using partner encryption_certificate" do
        # this is the interesting part.
        # alice will send a file to bob, who uses separate encryption & signing certs.
        bob_partner = build_multi_cert_partner('BOB', credentials: 'partner')
        refute_equal bob_partner.signing_certificate.to_pem, bob_partner.encryption_certificate.to_pem

        # this is the same as setup_integration_scenario
        # TODO: refactor setup_integration_scenario to accommodate multiple partner certificates
        alice_partner = build_partner('ALICE', credentials: 'client')
        alice_server_info = build_server_info('ALICE', credentials: 'client')
        bob_server_info = build_server_info('BOB', credentials: 'server')

        message_content = 'test message content'

        server_was_called = false
        bob_server = As2::Server.new(server_info: bob_server_info, partner: alice_partner)
        WebMock.stub_request(:post, bob_partner.url).to_return do |request|
          # LIMITATION: As2::Server doesn't currently support distinct signing and encryption certificates
          #   so we have to do some of the work here.
          #   we can sent TO a server which uses separate signing & encryption certs.
          #   but we can't current BE a server which uses separate signing & encryption certs.

          # prove that the message was encrypted using the expected partner_encryption.crt, from the bob_partner config
          # that alice_client used to send the message.
          bob_encryption_key = OpenSSL::PKey.read(File.read('test/certificates/partner_encryption.key'))
          bob_encryption_cert = OpenSSL::X509::Certificate.new(File.read('test/certificates/partner_encryption.crt'))
          message = As2::Message.new(request.body, bob_encryption_key, bob_encryption_cert)

          bob_server = As2::Server.new(server_info: bob_server_info, partner: alice_partner)

          # these would fail if we were unable to decrypt the message (using partner_encryption.key)
          assert message.decrypted_message.include?(Base64.strict_encode64(message_content))
          assert message.decrypted_message.include?("Content-Disposition: attachment; filename=data.txt")

          # assert that the message was signed with alice's cert.
          alice_signing_cert = OpenSSL::X509::Certificate.new(File.read('test/certificates/client.crt'))
          assert message.valid_signature?(alice_signing_cert)

          server_was_called = true
          {
            status: 500,
            headers: {},
            body: bob_server.send_mdn(env, )
          }
        end

        alice_client = As2::Client.new(bob_partner, server_info: alice_server_info)
        alice_client.send_file('data.txt', content: message_content)

        assert server_was_called
      end
    end

    describe 'body formats' do
      before do
        partner = build_partner('CLIENT', credentials: 'client')
        server_info = build_server_info('SERVER', credentials: 'server')
        @client = As2::Client.new(partner, server_info: server_info)
      end

      # confirm we retain the essential characteristics of this format
      it '#format_body_v0 builds a v0 message body' do
        document_part, body = @client.format_body_v0("document content", content_type: 'text/plain', file_name: 'test.txt')

        assert_equal("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=test.txt\r\n\r\nZG9jdW1lbnQgY29udGVudA==", document_part)
        assert_match(/Content-Type: multipart\/signed; protocol="application\/x-pkcs7-signature"; micalg="sha-256";/, body)
        assert_match(/This is an S\/MIME signed message\n\n/, body)
        assert_equal(body[-2..-1], "\n\n")
      end

      # confirm we retain the essential characteristics of this format
      it '#format_body_v1 builds a v1 message body' do
        document_part, body = @client.format_body_v1("document content", content_type: 'text/plain', file_name: 'test.txt')

        assert_equal("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=test.txt\r\n\r\nZG9jdW1lbnQgY29udGVudA==", document_part)
        assert_match(/Content-Type: multipart\/signed; protocol="application\/pkcs7-signature"; micalg=sha-256;/, body)
        refute_match(/This is an S\/MIME signed message\n\n/, body)
        assert_equal(body[-2..-1], "\r\n")
      end
    end

    As2::Client.valid_outbound_formats.each do |desired_outbound_format|
      describe "integration scenarios using outbound format #{desired_outbound_format}" do

        # TODO: can we send/receive a 0-byte file w/o error?

        describe 'when file_content is given' do
          it 'sends the given file content' do
            setup_integration_scenario(outbound_format: desired_outbound_format)

            file_name_received_by_bob = nil
            file_content_received_by_bob = nil

            @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner) do |file_name, body|
                            file_name_received_by_bob = file_name
                            file_content_received_by_bob = body.to_s
                          end

            file_name = 'data.txt'

            result = @alice_client.send_file(file_name, content: File.read('test/fixtures/message.txt'))

            assert_equal As2::Client::Result, result.class
            assert result.success
            assert result.mic_matched
            assert result.mid_matched
            assert_equal file_name, file_name_received_by_bob
            assert_equal File.read('test/fixtures/message.txt'), file_content_received_by_bob
          end
        end

        describe 'when file content has newlines' do
          # setup_integration_scenario

          # we do some gsub string manipulation in a few places in As2::Client
          # want to be sure this isn't affecting what is actually transmitted.
          it 'sends content correctly' do
            setup_integration_scenario(outbound_format: desired_outbound_format)

            file_name_received_by_bob = nil
            file_content_received_by_bob = nil

            @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner) do |file_name, body|
                            file_name_received_by_bob = file_name
                            file_content_received_by_bob = body.to_s
                          end

            file_name = 'data.txt'

            expected_content = "a\nb\tc\nd\r\ne\n"
            result = @alice_client.send_file(file_name, content: expected_content)

            assert_equal As2::Client::Result, result.class
            assert result.success
            assert result.signature_verified
            assert_nil result.signature_verification_error
            assert result.mic_matched
            assert result.mid_matched
            assert_equal file_name, file_name_received_by_bob
            assert_equal expected_content, file_content_received_by_bob
          end
        end

        describe 'when file_content is nil' do
          it 'reads content from file_name' do
            setup_integration_scenario(outbound_format: desired_outbound_format)

            file_name_received_by_bob = nil
            file_content_received_by_bob = nil

            @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner) do |file_name, body|
                            file_name_received_by_bob = file_name
                            file_content_received_by_bob = body.to_s
                          end

            file_path = 'test/fixtures/message.txt'
            dir_name = File.dirname(file_path)
            file_name = File.basename(file_path)

            Dir.chdir(dir_name) do
              result = @alice_client.send_file(file_name)

              assert_equal As2::Client::Result, result.class
              assert result.success
              assert result.signature_verified
              assert_nil result.signature_verification_error
              assert result.mic_matched
              assert result.mid_matched
              assert_equal file_name, file_name_received_by_bob
              assert_equal File.read(file_name), file_content_received_by_bob
            end
          end
        end

        describe 'non-ASCII content' do
          # not totally smooth due to character encoding. the bytes make it, but it's not a totally transparent process.
          # lower-priority issue since EDI is all ASCII, but worth being aware of & fixing at some point.
          # maybe Server could accept a parameter which tells us which character encoding to use?
          it 'is not mangled too horribly' do
            setup_integration_scenario(outbound_format: desired_outbound_format)

            file_name_received_by_bob = nil
            file_content_received_by_bob = nil

            @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner) do |file_name, body|
                            file_name_received_by_bob = file_name
                            file_content_received_by_bob = body.to_s
                          end

            file_name = 'data.txt'

            result = @alice_client.send_file(file_name, content: File.read('test/fixtures/multibyte.txt'))

            assert_equal As2::Client::Result, result.class

            assert result.success
            assert result.signature_verified
            assert_nil result.signature_verification_error
            assert result.mic_matched
            assert result.mid_matched
            assert_equal file_name, file_name_received_by_bob
            assert_equal File.read('test/fixtures/multibyte.txt', encoding: 'ASCII-8BIT'), file_content_received_by_bob
          end
        end
      end
    end
  end
end
