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

    def self.valid?(code)
      @map[normalized(code)]
    end

    def self.for_code(code)
      @map[normalized(code)] || OpenSSL::Digest::SHA1
    end

    def self.normalized(code)
      # we may receive 'sha256', 'sha-256', or 'SHA256'.
      code.to_s.strip.downcase.gsub(/[^a-z0-9]/, '')
    end
  end
end
