module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class CheckoutPaymentToken < PaymentToken
      def type
        'checkout'
      end
    end
  end
end