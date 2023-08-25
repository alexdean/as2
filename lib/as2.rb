require 'mail'
require 'openssl'
require 'securerandom'

require 'as2/client'
require 'as2/client/result'
require 'as2/config'
require 'as2/digest_selector'
require 'as2/parser/disposition_notification_options'
require 'as2/server'
require 'as2/version'

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

  # Select which algorithm to use for calculating a MIC, based on preferences
  # stated by sender & our list of available algorithms.
  #
  # @see https://datatracker.ietf.org/doc/html/rfc4130#section-7.3
  #
  # @param [String] disposition_notification_options The content of an HTTP
  #   Disposition-Notification-Options header
  # @return [String, nil] either an algorithm name, or nil if none is found in given header
  def self.choose_mic_algorithm(disposition_notification_options)
    parsed = As2::Parser::DispositionNotificationOptions.parse(disposition_notification_options)
    Array(parsed['signed-receipt-micalg']).find { |m| As2::DigestSelector.valid?(m) }
  end

  # surround an As2-From/As2-To value with double-quotes, if it contains a space.
  def self.quoted_system_identifier(name)
    if name.to_s.include?(' ')
      "\"#{name}\""
    else
      name
    end
  end
end
