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

  def self.valid_base64_schemes
    [
      'rfc2045', # https://www.rfc-editor.org/rfc/rfc2045#section-6.8
      'rfc4648'  # https://www.rfc-editor.org/rfc/rfc4648#section-4
    ]
  end

  # create a base64 string from content, based on the given encoding scheme
  #
  # @param [String] content
  # @param [String] scheme one of As2.valid_base64_schemes
  # @return [String]
  def self.base64_encode(content, scheme: 'rfc4648')
    case scheme
    when 'rfc2045'
      # "This method complies with RFC 2045."
      # https://ruby-doc.org/stdlib-3.0.4/libdoc/base64/rdoc/Base64.html#method-i-encode64
      then Base64.encode64(content)
    when 'rfc4648'
      # "This method complies with RFC 4648."
      # https://ruby-doc.org/stdlib-3.0.4/libdoc/base64/rdoc/Base64.html#method-i-strict_encode64
      then Base64.strict_encode64(content)
    else
      raise "unsupported base64_scheme '#{@partner.base64_scheme}'"
    end
  end

  # canonicalize all line endings in the given text.
  #
  #   "\n" becomes "\r\n"
  # "\r\n" remains "\r\n"
  #
  #   Conversion to canonical form:
  #   The entire body ... is converted to a universal canonical
  #   form. ... For example, in the case of text/plain data, the text
  #   must be converted to a supported character set and lines must
  #   be delimited with CRLF delimiters in accordance with RFC 822.
  #
  # https://www.rfc-editor.org/rfc/rfc2049#page-9
  #
  # @param [String] content
  # @return [String] content, but with all bare \n replaced by \r\n
  def self.canonicalize_line_endings(content)
    content.gsub(/(?<!\r)\n/, "\r\n")
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
    if name.to_s.include?(' ') && !name.to_s.start_with?('"')
      "\"#{name}\""
    else
      name
    end
  end

  # remove double-quotes from an As2-From/As2-To value, if it contains any.
  # this is useful in client code which may not automatically strip these quotes from a header value.
  def self.unquoted_system_identifier(name)
    if !name.is_a?(String)
      return name
    end

    name.delete_prefix('"').delete_suffix('"').gsub('\"', '"')
  end
end
