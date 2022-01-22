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
end
