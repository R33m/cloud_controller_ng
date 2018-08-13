require "rubygems"
require "serialgps"
module VCAP::CloudController
  module Security
    class SecurityContextConfigurer
      def initialize(token_decoder)
        @token_decoder = token_decoder
      end



    def location_of_user
       user_ip_address=request.remote_ip
       request.env["HTTP_X_FORWARDED_FOR"]
       user_location="public"
#get the gps lati and long using https://github.com/jgillick/ruby-serialgps/blob/master/README.rdoc
#gem install jgillick-ruby-serialgps
       device = "/dev/ttyUSB0"
       gps = SerialGPS.new(device)
       while true
      data = gps.read
       if data.key?(:latitude)
        current_lati= data[:latitude]
        current_long=data[:longitude]
       else
        return false
       end
      end
      if location_user_ip.find(ip_address:user_ip_address.to_s)!=nil
       return user_loaction="Office"
      elsif location_user_db.find(gps_long :current_long && gps_lati :current_lati)!=nil
       return user_loaction="Office"
      else
       return user_location
      end
    end

    def configure(header_token)
      VCAP::CloudController::SecurityContext.clear
      token_information = decode_token(header_token)

      user = user_from_token(token_information)
      user_location = location_of_user
      VCAP::CloudController::SecurityContext.set(user, token_information, header_token, user_loaction)
    rescue VCAP::CloudController::UaaTokenDecoder::BadToken
      VCAP::CloudController::SecurityContext.set(nil, :invalid_token, header_token, nil)
    end
      private

      def decode_token(header_token)
        token_information = @token_decoder.decode_token(header_token)
        return nil if token_information.nil? || token_information.empty?

        if !token_information['user_id'] && token_information['client_id']
          token_information['user_id'] = token_information['client_id']
        end
        token_information
      end

      def user_from_token(token)
        user_guid = token && token['user_id']
        return unless user_guid
        User.find(guid: user_guid.to_s) || User.create(guid: user_guid, active: true)
      rescue Sequel::ValidationFailed
        User.find(guid: user_guid.to_s)
      rescue Sequel::UniqueConstraintViolation
        User.find(guid: user_guid.to_s)
      end
    end
  end
end
