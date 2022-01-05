require 'openssl'

module As2
  class DigestSelector
    @map = {
      'sha1' => OpenSSL::Digest::SHA1,
      'sha256' => OpenSSL::Digest::SHA256,
      'sha384' => OpenSSL::Digest::SHA384,
      'sha512' => OpenSSL::Digest::SHA512,
      'md5' => OpenSSL::Digest::MD5
    }

    def self.valid_codes
      @map.keys
    end

    def self.for_code(code)
      normalized = code.strip.downcase.gsub(/[^a-z0-9]/, '')

      @map[normalized] || OpenSSL::Digest::SHA1
    end
  end
end
