require 'as2/base64_helper'

module As2
  class Message
    attr_reader :original_message

    def initialize(message, private_key, public_certificate)
      @original_message = message
      @private_key = private_key
      @public_certificate = public_certificate
    end

    def decrypted_message
      @decrypted_message ||= decrypt_smime(original_message)
    end

    def valid_signature?(partner)
      store = OpenSSL::X509::Store.new
      store.add_cert(partner.certificate)

      smime = Base64Helper.ensure_body_base64(decrypted_message)
      message = read_smime(smime)
      message.verify [partner.certificate], store
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

    def read_smime(smime)
      OpenSSL::PKCS7.read_smime(smime)
    end

    def decrypt_smime(smime)
      message = read_smime(smime)
      message.decrypt @private_key, @public_certificate
    end
  end
end
