module VCAP::CloudController
  class SpaceAccess < BaseAccess
    # These methods should be called first to determine if the user's token has the appropriate scope for the operation


   if VCAP::CloudController::SecurityContext.self.current_user_location=="Office"
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

    def read_related_object_for_update?(space, params=nil)
      read_for_update?(space, params)
    end

    def create?(space, params=nil)
      return true if context.queryer.can_write_globally?
      return false if space.in_suspended_org?
      context.queryer.can_write_to_org?(space.organization.guid)
    end

    def can_remove_related_object?(space, params)
      return true if admin_user?
      user_acting_on_themselves?(params) || read_for_update?(space, params)
    end

    def read_for_update?(space, params=nil)
      return true if context.queryer.can_write_globally?
      return false if space.in_suspended_org?
      context.queryer.can_write_to_org?(space.organization.guid) || context.queryer.can_update_space?(space.guid)
    end

    def update?(space, params=nil)
      read_for_update?(space, params)
    end

    def delete?(space)
      create?(space)
    end

  elsif  VCAP::CloudController::SecurityContext.self.current_user_location=="public"
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

   def read_related_object_for_update?(space, params=nil)
     return false
   end

   def create?(space, params=nil)
     return false
   end

   def can_remove_related_object?(space, params)
     return false
   end

   def read_for_update?(space, params=nil)
     return false
   end

   def update?(space, params=nil)
     return false
   end

   def delete?(space)
     return false
   end

  end

    def read_with_token?(_)
      admin_user? || admin_read_only_user? || has_read_scope? || global_auditor?
    end

    def index_with_token?(_)
      # This can return true because the index endpoints filter objects based on user visibilities
      true
    end

    def index?(object_class, params=nil)
      # This can return true because the index endpoints filter objects based on user visibilities
      true
    end

    private

    def user_acting_on_themselves?(options)
      [:auditors, :developers, :managers].include?(options[:relation]) && context.user.guid == options[:related_guid]
    end

  end
end
