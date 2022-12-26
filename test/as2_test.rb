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
    end
  end
end
