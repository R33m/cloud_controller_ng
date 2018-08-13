module VCAP::CloudController
  class SecurityGroupAccess < BaseAccess
  if VCAP::CloudController::SecurityContext.self.current_user_location=="Office"
    def create?(object, params=nil)
      admin_user?
    end

    def read_for_update?(object, params=nil)
      admin_user?
    end

    def can_remove_related_object?(object, params=nil)
      read_for_update?(object, params)
    end

    def read_related_object_for_update?(object, params=nil)
      read_for_update?(object, params)
    end

    def update?(object, params=nil)
      admin_user?
    end

    def delete?(object)
      admin_user?
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

  elsif VCAP::CloudController::SecurityContext.self.current_user_location=="public"
    def create?(object, params=nil)
      return false
    end

    def read_for_update?(object, params=nil)
      return false
    end

    def can_remove_related_object?(object, params=nil)
      return false
    end

    def read_related_object_for_update?(object, params=nil)
      return false
    end

    def update?(object, params=nil)
     return false
    end

    def delete?(object)
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
  end
end
