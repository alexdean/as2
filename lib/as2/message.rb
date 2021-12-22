require 'as2/base64_helper'

module As2
  class Message
    attr_reader :pkcs7

    def initialize(message, private_key, public_certificate)
      # TODO: might need to use OpenSSL::PKCS7.read_smime rather than .new sometimes
      @pkcs7 = OpenSSL::PKCS7.new(message)
      @private_key = private_key
      @public_certificate = public_certificate
    end

    def decrypted_message
      @decrypted_message ||= @pkcs7.decrypt @private_key, @public_certificate
    end

    def valid_signature?(partner_certificate)
      store = OpenSSL::X509::Store.new
      store.add_cert(partner_certificate)

      @pkcs7.verify [partner_certificate], store
    end

    def mic
      OpenSSL::Digest::SHA1.base64digest(attachment.raw_source.strip)
    end

    # Return the attached file, use .filename and .body on the return value
    def attachment
      if mail.has_attachments?
        mail.attachments.find{|a| a.content_type == "application/edi-consent"}
      else
        mail
      end
    end

    private

    def mail
      @mail ||= Mail.new(decrypted_message)
    end
  end
end
