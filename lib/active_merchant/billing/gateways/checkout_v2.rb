module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class CheckoutV2Gateway < Gateway
      self.display_name = 'Checkout.com Unified Payments'
      self.homepage_url = 'https://www.checkout.com/'
      self.live_url = 'https://api.checkout.com'
      self.test_url = 'https://api.sandbox.checkout.com'

      self.supported_countries = ['AD', 'AE', 'AT', 'BE', 'BG', 'CH', 'CY', 'CZ', 'DE', 'DK', 'EE', 'ES', 'FO', 'FI', 'FR', 'GB', 'GI', 'GL', 'GR', 'HR', 'HU', 'IE', 'IS', 'IL', 'IT', 'LI', 'LT', 'LU', 'LV', 'MC', 'MT', 'NL', 'NO', 'PL', 'PT', 'RO', 'SE', 'SI', 'SM', 'SK', 'SJ', 'TR', 'VA']
      self.default_currency = 'USD'
      self.money_format = :cents
      self.supported_cardtypes = [:visa, :master, :american_express, :diners_club, :maestro,  :discover]

      def initialize(options={})
        requires!(options, :secret_key)
        super
      end

      def get_payment(payment_id)
        post = { id: payment_id }

        commit(:get, :get_payment, post)
      end

      def get_actions(payment_id)
        post = { id: payment_id }

        commit(:get, :get_actions, post)
      end

      def purchase(amount, payment_method, options={})
        options[:capture] = true
        authorize(amount, payment_method, options)
      end

      def authorize(amount, payment_method, options={})
        post = {}
        post[:capture] = options[:capture] || false

        add_invoice(post, amount, options)
        add_payment_method(post, payment_method)
        add_customer_data(post, options)
        add_transaction_data(post, options)
        add_3ds(post, options)

        commit(:post, :authorize, post)
      end

      def capture(amount, authorization, options={})
        post = {}
        add_invoice(post, amount, options)
        add_customer_data(post, options)

        commit(:post, :capture, post, authorization)
      end

      def void(authorization, options={})
        post = {}
        commit(:post, :void, post, authorization)
      end

      def refund(amount, authorization, options={})
        post = {}
        add_invoice(post, amount, options)
        add_customer_data(post, options)

        commit(:post, :refund, post, authorization)
      end

      def verify(payment_method, options={})
        authorize(0, payment_method, options)
      end

      # Note: Tokenization needs the class to be initialized with the public key
      # e.g.
      # ActiveMerchant::Billing::CheckoutV2Gateway.new(
      #  secret_key: 'sk_test_1'
      #  public_key: 'sk_test_2'
      # )
      def tokenize_credit_card(credit_card, options={})
        if @options[:public_key].blank?
          raise KeyError, 'public_key is not present in options'
        end

        unless credit_card.is_a?(CreditCard)
          raise TypeError, 'credit_card must be of type CreditCard'
        end

        post = {
          type: 'card',
          number: credit_card.number,
          name: credit_card.name,
          cvv: credit_card.verification_value,
          expiry_month: format(credit_card.month, :two_digits),
          expiry_year: format(credit_card.year, :four_digits),
        }

        address = options[:billing_address]

        phone = build_phone(address)

        post[:billing_address] = build_billing_address(address)
        post[:phone] = phone

        commit(:post, :tokenize_credit_card, post)
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript.
          gsub(%r((Authorization: )[^\\]*)i, '\1[FILTERED]').
          gsub(%r(("number\\":\\")\d+), '\1[FILTERED]').
          gsub(%r(("cvv\\":\\")\d+), '\1[FILTERED]')
      end

      class CheckoutPaymentToken < PaymentToken
        def type
          'checkout_token'
        end
      end

      class CheckoutPaymentId < PaymentToken
        def type
          'checkout_id'
        end
      end

      private

      def add_invoice(post, money, options)
        post[:amount] = localized_amount(money, options[:currency])
        post[:reference] = options[:order_id]
        post[:currency] = options[:currency] || currency(money)
        if options[:descriptor_name] || options[:descriptor_city]
          post[:billing_descriptor] = {}
          post[:billing_descriptor][:name] = options[:descriptor_name] if options[:descriptor_name]
          post[:billing_descriptor][:city] = options[:descriptor_city] if options[:descriptor_city]
        end
        post[:metadata] = {}
        post[:metadata][:udf5] = application_id || 'ActiveMerchant'
      end

      def add_payment_method(post, payment_method)
        post[:source] = {}

        if payment_method.is_a?(CreditCard)
          add_credit_card(post, payment_method)

        elsif payment_method.is_a?(CheckoutPaymentToken)
          add_payment_token(post, payment_method)

        elsif payment_method.is_a?(CheckoutPaymentId)
          add_payment_id(post, payment_method)
        end
      end

      def add_credit_card(post, credit_card)
        post[:source][:type] = 'card'
        post[:source][:name] = credit_card.name
        post[:source][:number] = credit_card.number
        post[:source][:cvv] = credit_card.verification_value
        post[:source][:expiry_year] = format(credit_card.year, :four_digits)
        post[:source][:expiry_month] = format(credit_card.month, :two_digits)
      end

      def add_payment_token(post, token)
        post[:source][:type] = 'token'
        post[:source][:token] = token.payment_data
      end

      def add_payment_id(post, id)
        post[:source][:type] = 'id'
        post[:source][:id] = id.payment_data
      end

      def build_billing_address(address)
        return {} if address.blank?

        billing_address = {}
        billing_address[:address_line1] = address[:address1] unless address[:address1].blank?
        billing_address[:address_line2] = address[:address2] unless address[:address2].blank?
        billing_address[:city] = address[:city] unless address[:city].blank?
        billing_address[:state] = address[:state] unless address[:state].blank?
        billing_address[:country] = address[:country] unless address[:country].blank?
        billing_address[:zip] = address[:zip] unless address[:zip].blank?

        billing_address
      end

      def build_phone(address)
        return {} if address.blank?

        if !address[:phone].blank?
          return { number: address[:phone] }
        else
          return {}
        end
      end

      def add_customer_data(post, options)
        post[:customer] = {}
        post[:customer][:email] = options[:email] || nil
        post[:payment_ip] = options[:ip] if options[:ip]
        address = options[:billing_address]
        if(address && post[:source])
          post[:source][:billing_address] = build_billing_address(address)
          post[:source][:phone] = build_phone(address)
        end
      end

      def add_transaction_data(post, options={})
        post[:card_on_file] = true if options[:card_on_file] == true
        post[:payment_type] = 'Regular' if options[:transaction_indicator] == 1
        post[:payment_type] = 'Recurring' if options[:transaction_indicator] == 2
        post[:previous_payment_id] = options[:previous_charge_id] if options[:previous_charge_id]
      end

      def add_3ds(post, options)
        if options[:three_d_secure]
          post[:'3ds'] = {}
          post[:'3ds'][:enabled] = true
          post[:'3ds'][:eci] =  options[:eci] if options[:eci]
          post[:'3ds'][:cryptogram] =  options[:cavv] if options[:cavv]
          post[:'3ds'][:xid] =  options[:xid] if options[:xid]
          post[:'3ds'][:attempt_n3d] = options[:attempt_n3d] if options[:attempt_n3d]
        end
      end

      def api_request(method, url, post = nil, action)
        raw_response = response = nil

        begin
          if method != :get
            raw_response = ssl_request(method, url, post.to_json, headers(action))
          else
            raw_response = ssl_request(method, url, nil, headers(action))
          end

          response = parse(raw_response)
        rescue ResponseError => e
          raise unless(e.response.code.to_s =~ /4\d\d/)
          response = parse(e.response.body)
        end

        response
      end

      def commit(method, action, post, authorization = nil)
        url = url(post, action, authorization)
        response = api_request(method, url, post, action)

        if action == :capture && response.key?('_links')
          response['id'] = response['_links']['payment']['href'].split('/')[-1]
        end

        succeeded = success_from(response, action)

        response(action, succeeded, response)
      end

      def response(action, succeeded, response)
        successful_response = succeeded && action == :purchase || action == :authorize
        avs_result = successful_response ? avs_result(response) : nil
        cvv_result = successful_response ? cvv_result(response) : nil

        Response.new(
          succeeded,
          message_from(succeeded, response),
          response,
          authorization: authorization_from(response),
          error_code: error_code_from(succeeded, response),
          test: test?,
          avs_result: avs_result,
          cvv_result: cvv_result
        )
      end

      def headers(action)
        key = @options[:secret_key]
        key = @options[:public_key] if action == :tokenize_credit_card

        {
          'Authorization' => key,
          'Content-Type'  => 'application/json;charset=UTF-8'
        }
      end

      def url(post, action, authorization)
        if action == :authorize
          "#{base_url}/payments"
        elsif action == :capture
          "#{base_url}/payments/#{authorization}/captures"
        elsif action == :refund
          "#{base_url}/payments/#{authorization}/refunds"
        elsif action == :void
          "#{base_url}/payments/#{authorization}/voids"
        elsif action == :get_payment
          "#{base_url}/payments/#{post[:id]}"
        elsif action == :get_actions
          "#{base_url}/payments/#{post[:id]}/actions"
        elsif action == :tokenize_credit_card
          "#{base_url}/tokens"
        else
          "#{base_url}/payments/#{authorization}/#{action}"
        end
      end

      def base_url
        test? ? test_url : live_url
      end

      def avs_result(response)
        response['source'] && response['source']['avs_check'] ? AVSResult.new(code: response['source']['avs_check']) : nil
      end

      def cvv_result(response)
        response['source'] && response['source']['cvv_check'] ? CVVResult.new(response['source']['cvv_check']) : nil
      end

      def parse(body)
        JSON.parse(body)
      rescue JSON::ParserError
        {
          'message' => 'Invalid JSON response received from Checkout.com Unified Payments Gateway. Please contact Checkout.com if you continue to receive this message.',
          'raw_response' => scrub(body)
        }
      end

      def success_from(response, action = nil)
        if %i[get_payment authorize].include? action
          response.key?('id')
        elsif action == :get_actions
          response.is_a?(Array) && response.length > 0
        elsif action == :tokenize_credit_card
          response.key?('token')
        else
          response['response_summary'] == 'Approved' || !response.key?('response_summary') && response.key?('action_id')
        end
      end

      def message_from(succeeded, response)
        if succeeded
          'Succeeded'
        elsif response['error_type']
          response['error_type'] + ': ' + response['error_codes'].first
        else
          response['response_summary'] || response['response_code'] || 'Unable to read error message'
        end
      end

      STANDARD_ERROR_CODE_MAPPING = {
        '20014' => STANDARD_ERROR_CODE[:invalid_number],
        '20100' => STANDARD_ERROR_CODE[:invalid_expiry_date],
        '20054' => STANDARD_ERROR_CODE[:expired_card],
        '40104' => STANDARD_ERROR_CODE[:incorrect_cvc],
        '40108' => STANDARD_ERROR_CODE[:incorrect_zip],
        '40111' => STANDARD_ERROR_CODE[:incorrect_address],
        '20005' => STANDARD_ERROR_CODE[:card_declined],
        '20088' => STANDARD_ERROR_CODE[:processing_error],
        '20001' => STANDARD_ERROR_CODE[:call_issuer],
        '30004' => STANDARD_ERROR_CODE[:pickup_card]
      }

      def authorization_from(raw)
        raw.respond_to?(:key?) ? raw['id'] : nil
      end

      def error_code_from(succeeded, response)
        return if succeeded

        if response['error_type'] && response['error_codes']
          "#{response["error_type"]}: #{response["error_codes"].join(", ")}"
        elsif response['error_type']
          response['error_type']
        else
          STANDARD_ERROR_CODE_MAPPING[response['response_code']]
        end
      end
    end
  end
end
