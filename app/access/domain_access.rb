module VCAP::CloudController
  class DomainAccess < BaseAccess

  if VCAP::CloudController::SecurityContext.self.current_user_location=="Office"
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

    def create?(domain, params=nil)
      return true if admin_user?
      actual_access(domain).create?(domain, params)
    end

    def read_for_update?(domain, params=nil)
      actual_access(domain).read_for_update?(domain, params)
    end

    def update?(domain, params=nil)
      actual_access(domain).update?(domain, params)
    end

    def delete?(domain)
      actual_access(domain).delete?(domain)
    end
elsif VCAP::CloudController::SecurityContext.self.current_user_location=="public"
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

  def create?(domain, params=nil)
    return false
  end

  def read_for_update?(domain, params=nil)
    return false
  end

  def update?(domain, params=nil)
    return false
  end

  def delete?(domain)
    return false
  end
end
    def read?(domain)
      actual_access(domain).read?(domain)
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

    def actual_access(domain)
      if domain.owning_organization
        PrivateDomainAccess.new(context)
      else
        SharedDomainAccess.new(context)
      end
    end
  end
end
