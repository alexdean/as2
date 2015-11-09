require 'base64'

module As2
  module Base64Helper
    # Will base64 encoded string, unless it already is base64 encoded
    def self.ensure_base64(string)
      begin
        # If string is not base64 encoded, this will raise an ArgumentError
        Base64.strict_decode64(string.gsub("\n",""))
        return string
      rescue ArgumentError
        # The string is not yet base64 encoded
        return Base64.encode64(string)
      end
    end
  end

  # If the multipart body is binary encoded, replace it with base64 encoded version
  def self.ensure_body_base64(multipart)
    boundary = multipart.scan(/boundary="([^"]*)"/)[0][0]
    boundary_split = Regexp.escape("--#{boundary}")
    parts = multipart.split(/^#{boundary_split}-*\s*$/)
    signature = parts[2]
    transfer_encoding = signature.scan(/Content-Transfer-Encoding: (.*)/)[0][0].strip
    if transfer_encoding == 'binary'
      header, body = signature.split(/^\s*$/,2).map(&:lstrip)
      body_base64 = Base64.encode64(body)
      new_header = header.sub('Content-Transfer-Encoding: binary', 'Content-Transfer-Encoding: base64')
      parts[2] = new_header + "\r\n" + body_base64
      new_multipart = parts.join("--#{boundary}\r\n") + "--#{boundary}--\r\n"
      return new_multipart
    else
      return multipart
    end
  end
end
