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

    # @return [Array] all the codes we understand
    def self.valid_codes
      @map.keys
    end

    # @param [String] code an algorithm identifier like 'sha256' or 'md5'
    # @return [boolean] do we recognize this code?
    def self.valid_code?(code)
      normalized = normalize(code)
      valid_codes.include?(normalized)
    end

    # @param [String] code an algorithm identifier like 'sha256' or 'md5'
    # @return [Class] an OpenSSL::Digest class implementing the requested algorithm
    #   returns OpenSSL::Digest::SHA1 if the requested code is not recognized
    def self.for_code(code)
      normalized = normalize(code)
      @map[normalized] || OpenSSL::Digest::SHA1
    end

    private

    def self.normalize(code)
      # we may receive 'sha256', 'sha-256', or 'SHA256'.
      code.strip.downcase.gsub(/[^a-z0-9]/, '')
    end
  end
end
