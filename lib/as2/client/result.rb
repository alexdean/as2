module As2
  class Client
    class Result
      attr_reader :response, :mic_matched, :mid_matched, :body, :disposition, :signature_verification_error, :exception, :outbound_message_id

      def initialize(response:, mic_matched:, mid_matched:, body:, disposition:, signature_verification_error:, exception:, outbound_message_id:)
        @response = response
        @mic_matched = mic_matched
        @mid_matched = mid_matched
        @body = body
        @disposition = disposition
        @signature_verification_error = signature_verification_error
        @exception = exception
        @outbound_message_id = outbound_message_id
      end

      def signature_verified
        self.signature_verification_error.nil?
      end

      # legacy name. accessor for backwards-compatibility.
      def disp_code
        self.disposition
      end

      def success
        # TODO: we'll never have success if MDN is unsigned.
        self.signature_verified &&
        self.mic_matched &&
        self.mid_matched &&
        self.disposition&.include?('processed')
      end
    end
  end
end
