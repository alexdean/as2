require 'test_helper'

describe As2::Client do
  after do
    As2.reset_config!
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

  describe '#send_file' do
    before do
      # scenario: Alice is sending a message to Bob.
      @alice_partner = build_partner('ALICE', credentials: 'client')
      @alice_server_info = build_server_info('ALICE', credentials: 'client')

      @bob_partner = build_partner('BOB', credentials: 'server')
      @bob_server_info = build_server_info('BOB', credentials: 'server')

      @alice_client = As2::Client.new(@bob_partner, server_info: @alice_server_info)
      # individual tests will provide a different @bob_server if they want to assert on its behavior
      @bob_server = As2::Server.new(server_info: @bob_server_info, partner: @alice_partner)

      stub_request(:post, @bob_partner.url).to_return do |request|
        # do all the HTTP things that rack would do during a real request
        headers = request.headers.transform_keys {|k| "HTTP_#{k.upcase}".gsub('-', '_') }
        env = Rack::MockRequest.env_for(request.uri.path, headers.merge(input: request.body))

        # then hand off the content to @bob_server (which must be defined by the actual tests below)
        status, headers, body = @bob_server.call(env)
        {
          status: status,
          headers: headers,
          body: body.first
        }
      end
    end

    it 'captures and returns any exception raised while processing MDN response' do
      expected_error_message = "error parsing attachment"
      mail_replacment = ->(*args) { raise expected_error_message }

      Mail.stub(:new, mail_replacment) do
        result = @alice_client.send_file('file_name.txt', content: 'file content')

        assert_equal RuntimeError, result.exception.class
        assert_equal expected_error_message, result.exception.message
        assert_equal false, result.success
      end
    end

    it "parses an MDN with a 'disposition:' header" # eg: "disposition: automatic-action/MDN-sent-automatically; processed"
    it "parses an MDN with extended 'Content-Type:'" # eg: 'Content-Type: text/plain; charset="UTF-8"'
    it "parses an MDN which is missing 'Received-Content-MIC:'"

    # these are really 'dogfood' tests using both As2::Client and As2::Server.
    describe 'integration scenarios' do
      # TODO: can we send/receive a 0-byte file w/o error?

      describe 'when file_content is given' do
        it 'sends the given file content' do
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
        # we do some gsub string manipulation in a few places in As2::Client
        # want to be sure this isn't affecting what is actually transmitted.
        it 'sends content correctly' do
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
