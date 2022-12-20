module As2
  class Message
    attr_reader :verification_error

    # given multiple parts of a message, choose the one most likely to be the actual content we care about
    #
    # @param [Array<Mail::Part>]
    # @return [Mail::Part, nil]
    def self.choose_attachment(mail_parts)
      return nil if mail_parts.nil?

       # if there are multiple content parts, try to prefer the EDI content.
      candidates = mail_parts
                   .select { |part| part.content_type.to_s['pkcs7-signature'].nil? } # skip signature
                   .sort_by { |part| part.content_type.to_s.match(/^application\/edi/i) ? 0 : 1 }
      candidates[0]
    end

    # @param [Mail::Part] attachment
    # @param [String] mic_algorithm
    # @return [String] message integrity check string
    def self.mic(attachment, mic_algorithm)
      digest = As2::DigestSelector.for_code(mic_algorithm)
      digest.base64digest(attachment.raw_source.lstrip)
    end

    def self.verify(content:, signature_text:, certificate:)
      signature = OpenSSL::PKCS7.new(signature_text)

      # using an empty CA store. see notes on NOVERIFY flag below.
      store = OpenSSL::X509::Store.new

      # notes on verification proces and flags used
      #
      # ## NOINTERN
      #
      # > If PKCS7_NOINTERN is set the certificates in the message itself are
      # > not searched when locating the signer's certificate. This means that
      # > all the signers certificates must be in the certs parameter.
      #
      # > One application of PKCS7_NOINTERN is to only accept messages signed
      # > by a small number of certificates. The acceptable certificates would
      # > be passed in the certs parameter. In this case if the signer is not
      # > one of the certificates supplied in certs then the verify will fail
      # > because the signer cannot be found.
      #
      # https://www.openssl.org/docs/manmaster/man3/PKCS7_verify.html
      #
      # we want this so we can be sure that the `partner_certificate` we supply
      # was actually used to sign the message. otherwise we could get a positive
      # verification even if `partner_certificate` didn't sign the message
      # we're checking.
      #
      # ## NOVERIFY
      #
      # > If PKCS7_NOVERIFY is set the signer's certificates are not chain verified.
      #
      # ie: we won't attempt to connect signer (in the first param) to a root
      # CA (in `store`, which is empty). alternately, we could instead remove
      # this flag, and add `partner_certificate` to `store`. but what's the point?
      # we'd only be verifying that `partner_certificate` is connected to `partner_certificate`.
      valid = signature.verify([certificate], store, content, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN)

      {
        valid: valid,
        # when `signature.verify` fails, signature.error_string will be populated.
        error: signature.error_string
      }
    end

    def initialize(message, private_key, public_certificate)
      # TODO: might need to use OpenSSL::PKCS7.read_smime rather than .new sometimes
      @pkcs7 = OpenSSL::PKCS7.new(message)
      @private_key = private_key
      @public_certificate = public_certificate
      @verification_error = nil
      @updated_body_due_to_lineending_workaround = nil
    end

    def decrypted_message
      @decrypted_message ||= @pkcs7.decrypt @private_key, @public_certificate
    end

    def valid_signature?(partner_certificate)
      content_type = mail.header_fields.find { |h| h.name == 'Content-Type' }.content_type
      if content_type == "multipart/signed"
        # for a "multipart/signed" message, we will do 'detatched' signature
        # verification, where we supply the data to be verified as the 3rd parameter
        # to OpenSSL::PKCS7#verify. this is in keeping with how this content type
        # is described in the S/MIME RFC.
        #
        # > The multipart/signed MIME type has two parts.  The first part contains
        # > the MIME entity that is signed; the second part contains the "detached signature"
        # > CMS SignedData object in which the encapContentInfo eContent field is absent.
        #
        # https://datatracker.ietf.org/doc/html/rfc3851#section-3.4.3.1

        # TODO: more robust detection of content vs signature (if they're ever out of order).
        content = mail.parts[0].raw_source
        # remove any leading \r\n characters (between headers & body i think).
        content = content.gsub(/\A\s+/, '')

        signature_text = mail.parts[1].body.to_s

        result = self.class.verify(
                                    content: content,
                                    signature_text: signature_text,
                                    certificate: partner_certificate
                                  )

        output = result[:valid]
        @verification_error = result[:error]

        # HACK workaround fix for https://github.com/mikel/mail/pull/1511
        #
        # due to a bug in the mail gem, the actual message body we receive can
        # have all "\n" replaced by "\r\n" when using 'Content-Transfer-Encoding: binary'.
        # if we line endings back to "\n", then signature verification is successful.
        # this entire block can be removed once that is released & integrated into as2.
        #
        # we don't really know that verification failed due to line-ending mismatch.
        # it's only a guess.
        if !output && mail.parts[0].content_transfer_encoding == 'binary'
          body_delimiter = "\r\n\r\n"
          parts = content.split(body_delimiter)
          headers = parts[0]
          body = parts[1..].join(body_delimiter)
          body.gsub!("\r\n", "\n")
          content = headers + body_delimiter + body

          signature = OpenSSL::PKCS7.new(mail.parts[1].body.to_s)
          retry_output = self.class.verify(
                                            content: content,
                                            signature_text: signature_text,
                                            certificate: partner_certificate
                                          )

          if retry_output[:valid]
            @updated_body_due_to_lineending_workaround = content
            output = retry_output[:valid]
            @verification_error = retry_output[:error]
          end
        end

        output
      else
        # TODO: how to log this?
        false
      end
    end

    def mic
      if @updated_body_due_to_lineending_workaround
        body_part = Mail::Part.new(@updated_body_due_to_lineending_workaround)
      else
        body_part = attachment
      end

      self.class.mic(body_part, mic_algorithm)
    end

    def mic_algorithm
      'sha256'
    end

    # Return the attached file, use .filename and .body on the return value
    def attachment
      self.class.choose_attachment(parts)
    end

    def parts
      mail&.parts
    end

    private

    def mail
      @mail ||= Mail.new(decrypted_message)
    end
  end
end
