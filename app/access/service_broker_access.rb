module VCAP::CloudController
  class ServiceBrokerAccess < BaseAccess
  if VCAP::CloudController::SecurityContext.self.current_user_location=="Office"
    def read_for_update?(object, params=nil)
      admin_user?
    end

    def can_remove_related_object?(object, params=nil)
      read_for_update?(object, params)
    end

    def read_related_object_for_update?(object, params=nil)
      read_for_update?(object, params)
    end

    # These methods should be called first to determine if the user's token has the appropriate scope for the operation

    def create_with_token?(_)
      admin_user? || has_write_scope?
    end

    def read_for_update_with_token?(_)
      admin_user? || has_write_scope?
    end

    def can_remove_related_object_with_token?(*args)
      read_for_update_with_token?(*args)
    end

    def read_related_object_for_update_with_token?(*args)
      read_for_update_with_token?(*args)
    end

    def update_with_token?(_)
      admin_user? || has_write_scope?
    end

    def delete_with_token?(_)
      admin_user? || has_write_scope?
    end

    def create?(service_broker, _=nil)
      return true if admin_user?
      FeatureFlag.raise_unless_enabled!(:space_scoped_private_broker_creation)

      unless service_broker.nil?
        return validate_object_access(service_broker)
      end
    end

    def update?(service_broker, _=nil)
      return true if admin_user?

      unless service_broker.nil?
        return validate_object_access(service_broker)
      end

      false
    end

    def delete?(service_broker, _=nil)
      return true if admin_user?

      unless service_broker.nil?
        return validate_object_access(service_broker)
      end

      false
    end
  elsif VCAP::CloudController::SecurityContext.self.current_user_location=="public"
    def read_for_update?(object, params=nil)
        return false
    end

    def can_remove_related_object?(object, params=nil)
        return false
    end

    def read_related_object_for_update?(object, params=nil)
        return false
    end

    # These methods should be called first to determine if the user's token has the appropriate scope for the operation

    def create_with_token?(_)
        return false
    end

    def read_for_update_with_token?(_)
        return false
    end

    def can_remove_related_object_with_token?(*args)
      return false
    end

    def read_related_object_for_update_with_token?(*args)
        return false
    end

    def update_with_token?(_)
        return false
    end

    def delete_with_token?(_)
      return false
    end

    def create?(service_broker, _=nil)
      return false
    end

    def update?(service_broker, _=nil)
        return false
    end

    def delete?(service_broker, _=nil)

      return false
    end

  end

    def read?(object)
      return @ok_read if instance_variable_defined?(:@ok_read)
      @ok_read = (admin_user? || admin_read_only_user? || global_auditor? || object_is_visible_to_user?(object, context.user))
    end

    def index?(object_class, params=nil)
      # This can return true because the index endpoints filter objects based on user visibilities
      true
    end
    # These methods should be called first to determine if the user's token has the appropriate scope for the operation

    def read_with_token?(_)
      admin_user? || admin_read_only_user? || has_read_scope? || global_auditor?
    end

    def index_with_token?(_)
     # This can return true because the index endpoints filter objects based on user visibilities
     true
    end

    private

    def validate_object_access(service_broker)
      if service_broker.private?
        service_broker.space.has_developer?(context.user)
      else
        false
      end
    end
  end
end
