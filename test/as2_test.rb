require 'test_helper'

describe As2 do
  describe '.generate_message_id' do
    it 'creates a message id string based on given server_info' do
      server_info = build_server_info('BOB', credentials: 'server')

      message_ids = []
      5.times do
        message_id = As2.generate_message_id(server_info)
        message_ids << message_id
        assert message_id.match(/^\<#{server_info.name}-\d{8}-\d{6}-[a-f0-9\-]{36}@#{server_info.domain}\>$/), "'#{message_id}' does not match expected pattern."
      end

      assert_equal 5, message_ids.uniq.size
    end
  end

  describe '.base64_encode' do
    before(:all) do
      @ascii = (32..126).map(&:chr).join.freeze
      @binary = File.open('test/fixtures/white-box.png', 'rb').read.freeze
      @utf8 = "こんにちは".freeze
    end

    describe 'with rfc2045 rules' do
      it 'can encode all printable ascii characters' do
        encoded = As2.base64_encode(@ascii, scheme: 'rfc2045')
        decoded = Base64.decode64(encoded)
        assert_equal @ascii, decoded
      end

      it 'can encode arbitrary binary data' do
        encoded = As2.base64_encode(@binary, scheme: 'rfc2045')
        decoded = Base64.decode64(encoded)
        assert_equal @binary, decoded
      end

      it 'can encode UTF-8' do
        encoded = As2.base64_encode(@utf8, scheme: 'rfc2045')
        decoded = Base64.decode64(encoded)
        decoded.force_encoding('UTF-8')
        assert_equal @utf8, decoded
      end
    end

    describe 'with rfc4648 rules' do
      it 'can encode all printable ascii characters' do
        encoded = As2.base64_encode(@ascii, scheme: 'rfc4648')
        decoded = Base64.strict_decode64(encoded)
        assert_equal @ascii, decoded
      end

      it 'can encode arbitrary binary data' do
        encoded = As2.base64_encode(@binary, scheme: 'rfc4648')
        decoded = Base64.strict_decode64(encoded)
        assert_equal @binary, decoded
      end

      it 'can encode UTF-8' do
        encoded = As2.base64_encode(@utf8, scheme: 'rfc4648')
        decoded = Base64.decode64(encoded)
        decoded.force_encoding('UTF-8')
        assert_equal @utf8, decoded
      end
    end

    it 'raises if the given encoding scheme is not recognized' do
      error = assert_raises(ArgumentError) do
                As2.base64_encode(@binary, scheme: 'blah')
              end
      assert_equal "unsupported scheme 'blah'. choose one of: [\"rfc2045\", \"rfc4648\"]", error.message
    end

    it 'defaults to RFC-4648 for backwards-compatibility' do
      expected = As2.base64_encode(@ascii, scheme: 'rfc4648')
      assert_equal expected, As2.base64_encode(@ascii)
    end
  end

  describe '.canonicalize_line_endings' do
    it 'replaces \n with \r\n' do
      input = "a\nb\nc\n"
      expected = "a\r\nb\r\nc\r\n"
      assert_equal expected, As2.canonicalize_line_endings(input)
    end

    it 'does not alter existing \r\n sequences' do
      input = "a\r\nb\nc\n"
      expected = "a\r\nb\r\nc\r\n"
      assert_equal expected, As2.canonicalize_line_endings(input)
    end

    it 'does not add trailing newlines if string does not end with a newline' do
      input = "a"
      expected = "a"
      assert_equal expected, As2.canonicalize_line_endings(input)
    end

    it 'is compatible with all base64_encode schemes' do
      ascii = (32..126).map(&:chr).join.freeze
      input = ascii * 10 # long enough to be split onto multiple lines in rfc2045

      # if a new scheme is added, this assertion will remind us to test it here also.
      valid_schemes = As2.valid_base64_schemes
      assert_equal(['rfc2045', 'rfc4648'], valid_schemes)

      encoded = As2.base64_encode(input, scheme: 'rfc2045')
      canonicalized = As2.canonicalize_line_endings(encoded)
      decoded = Base64.decode64(encoded)
      assert_equal input, decoded

      encoded = As2.base64_encode(input, scheme: 'rfc4648')
      canonicalized = As2.canonicalize_line_endings(encoded)
      decoded = Base64.strict_decode64(encoded)
      assert_equal input, decoded
    end
  end

  describe '.choose_mic_algorithm' do
    it 'returns nil if no algorithm is found' do
      assert_nil As2.choose_mic_algorithm(nil)
      assert_nil As2.choose_mic_algorithm('')
    end

    it 'selects best mic algorithm from HTTP header' do
      header_value = 'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, SHA256'
      assert_equal 'SHA256', As2.choose_mic_algorithm(header_value)
    end

    it 'returns nil if no options are valid' do
      header_value = 'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, xxx, yyy'
      assert_nil As2.choose_mic_algorithm(header_value)
    end

    it 'returns first acceptable algo if client specifies multiple valid options' do
      header_value = 'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, invalid, sha1, md5'
      assert_equal 'sha1', As2.choose_mic_algorithm(header_value)

      header_value = 'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, invalid, md5, sha1'
      assert_equal 'md5', As2.choose_mic_algorithm(header_value)
    end
  end

  describe '.quoted_system_identifier' do
    it 'returns the string unchanged if it does not contain a space' do
      assert_equal 'A', As2.quoted_system_identifier('A')
    end

    it 'surrounds name with double-quotes if it contains a space' do
      assert_equal '"A A"', As2.quoted_system_identifier('A A')
    end

    it 'returns non-string inputs unchanged' do
      assert_nil As2.quoted_system_identifier(nil)
      assert_equal 1, As2.quoted_system_identifier(1)
      assert_equal true, As2.quoted_system_identifier(true)
      assert_equal :symbol, As2.quoted_system_identifier(:symbol)
      assert_equal({}, As2.quoted_system_identifier({}))
    end

    it 'does not re-quote a string which is already quoted' do
      assert_equal '"A A"', As2.quoted_system_identifier('"A A"')
    end
  end

  describe '.unquoted_system_identifier' do
    it 'removes leading/trailing double-quotes if present' do
      assert_equal 'AA', As2.unquoted_system_identifier('"AA"')
      assert_equal 'A A', As2.unquoted_system_identifier('"A A"')
    end

    it 'does nothing to a string which do not contain leading/trailing double-quotes' do
      assert_equal 'AA', As2.unquoted_system_identifier('AA')
      assert_equal 'A A', As2.unquoted_system_identifier('A A')
    end

    it 'unescapes interior double-quotes' do
      assert_equal 'A"A', As2.unquoted_system_identifier('"A\"A"')
    end

    it 'returns non-string inputs unchanged' do
      assert_nil As2.unquoted_system_identifier(nil)
      assert_equal 1, As2.unquoted_system_identifier(1)
      assert_equal true, As2.unquoted_system_identifier(true)
      assert_equal :symbol, As2.unquoted_system_identifier(:symbol)
      assert_equal({}, As2.unquoted_system_identifier({}))
    end
  end
end
