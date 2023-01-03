require 'test_helper'

describe As2::Parser::DispositionNotificationOptions do
  describe '.parse' do
    it 'understands header sent by OpenAS2' do
      result = As2::Parser::DispositionNotificationOptions.parse(
        'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha256'
      )
      assert_nil result.value
      assert_equal ['optional', 'pkcs7-signature'], result['signed-receipt-protocol']
      assert_equal ['optional', 'sha256'], result['signed-receipt-micalg']

      result = As2::Parser::DispositionNotificationOptions.parse(
        'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, md5'
      )
      assert_nil result.value
      assert_equal ['optional', 'pkcs7-signature'], result['signed-receipt-protocol']
      assert_equal ['optional', 'md5'], result['signed-receipt-micalg']
    end

    it 'understands header sent by Mendelson' do
      result = As2::Parser::DispositionNotificationOptions.parse(
        'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, SHA256'
      )
      assert_nil result.value
      assert_equal ['optional', 'pkcs7-signature'], result['signed-receipt-protocol']
      assert_equal ['optional', 'SHA256'], result['signed-receipt-micalg']
    end

    it 'allows case-insensitive access' do
      result = As2::Parser::DispositionNotificationOptions.parse(
        'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, SHA256'
      )
      assert_equal ['optional', 'pkcs7-signature'], result['signed-receipt-protocol']
      assert_equal ['optional', 'pkcs7-signature'], result['Signed-Receipt-Protocol']

      result = As2::Parser::DispositionNotificationOptions.parse(
        'signed-receipt-protocol=optional, pkcs7-signature; Signed-Receipt-Micalg=optional, SHA256'
      )
      assert_equal ['optional', 'SHA256'], result['signed-receipt-micalg']
      assert_equal ['optional', 'SHA256'], result['Signed-Receipt-Micalg']
    end

    # tests for parsing other headers
    #
    # following the way `mail` approaches this, using a different parser class
    # for each header. seems better since i'm not sure all headers follow these
    # same encoding rules.
    #
    # so... unsure if these tests will be used, but i have a guess they may come
    # in handy in the future so keeping them around.
    #
    # it 'does stuff' do
    #   result = As2::HeaderParser.parse_body(
    #     'application/pkcs7-mime; name=smime.p7m;    smime-type=enveloped-data'
    #   )
    #   assert_equal 'application/pkcs7-mime', result.value
    #   assert_equal 'smime.p7m', result['name']
    #   assert_equal 'enveloped-data', result['smime-type']

    #   # can remove quotes from values
    #   result = As2::HeaderParser.parse_body(
    #     'application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data'
    #   )
    #   assert_equal 'application/pkcs7-mime', result.value
    #   assert_equal 'smime.p7m', result['name']
    #   assert_equal 'enveloped-data', result['smime-type']

    #   # single values are strings
    #   result = As2::HeaderParser.parse_body(
    #     'attachment; filename=smime.p7m'
    #   )
    #   assert_equal 'attachment', result.value
    #   assert_equal 'smime.p7m', result['filename']

    #   # missing attributes are nil
    #   result = As2::HeaderParser.parse_body(
    #     'attachment'
    #   )
    #   assert_equal 'attachment', result.value
    #   assert_nil result['filename']

    #   # repeated values are arrays
    #   # missing value is nil
    #   result = As2::HeaderParser.parse_body(
    #     'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, SHA256'
    #   )
    #   assert_nil result.value
    #   assert_equal ['optional', 'pkcs7-signature'], result['signed-receipt-protocol']
    #   assert_equal ['optional', 'SHA256'], result['signed-receipt-micalg']

    #   # no extra parsing of strings with spaces
    #   result = As2::HeaderParser.parse_body(
    #     'File 204_Test OUT_XXXX.edi sent from Sender to Receiver'
    #   )
    #   assert_equal 'File 204_Test OUT_XXXX.edi sent from Sender to Receiver', result.value

    #   # attribute names get lowercased
    #   result = As2::HeaderParser.parse_body(
    #     'application/pkcs7-mime; NAME="smime.p7m"; SMIME-TYPE=enveloped-data'
    #   )
    #   assert_equal 'smime.p7m', result['name']
    #   assert_equal 'enveloped-data', result['smime-type']
    # end
  end
end
