require 'openssl'
require 'mail'
require 'securerandom'
require 'as2/config'
require 'as2/server'
require 'as2/client'
require 'as2/header_parser'
require 'as2/client/result'
require 'as2/digest_selector'
require "as2/version"

module As2
  def self.configure(&block)
    Config.configure(&block)
  end

  def self.reset_config!
    Config.reset!
  end

  def self.generate_message_id(server_info)
    "<#{server_info.name}-#{Time.now.strftime('%Y%m%d-%H%M%S')}-#{SecureRandom.uuid}@#{server_info.domain}>"
  end

  def self.choose_mic_algorithm(disposition_notification_options)
    parsed = As2::HeaderParser.parse_body(disposition_notification_options)
    Array(parsed['signed-receipt-micalg']).find { |m| As2::DigestSelector.valid?(m) }
  end
end
