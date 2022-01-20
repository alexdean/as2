require 'test_helper'

describe As2::Client::Result do
  before do
    @attributes = {
      disposition: 'automatic-action/MDN-sent-automatically; processed',
      signature_verification_error: nil,
      mic_matched: true,
      mid_matched: true,
      response: nil,
      body: nil,
      exception: nil,
      outbound_message_id: nil
    }
  end

  describe '#success' do
    it 'is true when everything looks good' do
      subject = As2::Client::Result.new(@attributes)
      assert subject.success
    end

    it 'is true on disposition processed/warning' do
      @attributes[:disposition] = 'automatic-action/MDN-sent-automatically; processed/Warning: authentication-failed, processing continued'
      subject = As2::Client::Result.new(@attributes)
      assert subject.success
    end

    it 'is false on disposition processed/error' do
      @attributes[:disposition] = 'automatic-action/MDN-sent-automatically; processed/error: authentication-failed'
      subject = As2::Client::Result.new(@attributes)
      assert !subject.success
    end

    it 'is false if there are signature verification issues' do
      @attributes[:signature_verification_error] = 'missing certificate'
      subject = As2::Client::Result.new(@attributes)
      assert !subject.success
    end
  end

  describe '#signature_verified' do
    it 'is true if signature_verification_error is nil' do
      @attributes[:signature_verification_error] = nil
      subject = As2::Client::Result.new(@attributes)
      assert subject.signature_verified
    end

    it 'is false if signature_verification_error is present' do
      @attributes[:signature_verification_error] = 'missing certificate'
      subject = As2::Client::Result.new(@attributes)
      assert !subject.signature_verified
    end
  end
end
