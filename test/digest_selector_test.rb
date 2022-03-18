require 'test_helper'

describe As2::DigestSelector do
  describe '.for_code' do
    it 'can build a base64digest for all supported algorithm codes' do
      As2::DigestSelector.valid_codes.each do |code|
        assert As2::DigestSelector.for_code(code).base64digest("message body")
      end
    end

    it 'normalizes common code variants' do
      expected = OpenSSL::Digest::SHA256

      assert_equal expected, As2::DigestSelector.for_code('sha256')
      assert_equal expected, As2::DigestSelector.for_code('SHA256')
      assert_equal expected, As2::DigestSelector.for_code('sha-256')
    end

    # not sure if this is better or if we should raise.
    # current thinking is: "MDN verification failure" > "raising an exception"
    it 'defaults to SHA1 if code is unrecognized' do
      assert_equal OpenSSL::Digest::SHA1, As2::DigestSelector.for_code('blat')
    end
  end
end
