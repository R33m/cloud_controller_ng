module VCAP::CloudController
  class OrganizationAccess < BaseAccess

if VCAP::CloudController::SecurityContext.self.current_user_location=="Office"
    def create?(org, params=nil)
      return true if context.queryer.can_write_globally?
      FeatureFlag.enabled?(:user_org_creation)
    end

    def read_for_update?(org, params=nil)
      return true if context.queryer.can_write_globally?
      return false unless org.active?
      return false unless context.queryer.can_write_to_org?(org.guid)

      if params.present?
        return false if params.key?(:quota_definition_guid.to_s) || params.key?(:billing_enabled.to_s)
      end

      true
    end

    def can_remove_related_object?(org, params={})
      return true if context.queryer.can_write_globally?

      user_acting_on_themselves = user_acting_on_themselves?(params)
      return false unless context.queryer.can_write_to_org?(org.guid) || user_acting_on_themselves
      return false unless org.active?
      validate!(org, params)

      user_acting_on_themselves || read_for_update?(org, params)
    end

    def update?(org, params=nil)
      return true if context.queryer.can_write_globally?
      return false unless org.active?
      context.queryer.can_write_to_org?(org.guid)
    end

    def delete?(object)
      context.queryer.can_write_globally?
    end




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


    def read_with_token?(_)
      admin_user? || admin_read_only_user? || has_read_scope? || global_auditor?
    end
elsif VCAP::CloudController::SecurityContext.self.current_user_location=="public"
  def create?(org, params=nil)
    return false
  end

  def read_for_update?(org, params=nil)
    return false

    if params.present?
      return false
    end

    true
  end

  def can_remove_related_object?(org, params={})
    return false

    user_acting_on_themselves = user_acting_on_themselves?(params)
    return false
    validate!(org, params)

    user_acting_on_themselves || read_for_update?(org, params)
  end

  def update?(org, params=nil)
  return false
  end

  def delete?(object)
    return false
  end

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

  def read_with_token?(_)
    return false
  end
end
def index?(_, params=nil)
  true
end
def index_with_token?(_)
  # This can return true because the index endpoints filter objects based on user visibilities
  true
end
    private

    def user_acting_on_themselves?(options)
      [:auditors, :billing_managers, :managers, :users].include?(options[:relation]) && context.user&.guid == options[:related_guid]
    end

    def validate!(org, params)
      validate_remove_billing_manager_by_guid!(org) if params[:relation] == :billing_managers
      validate_remove_manager_by_guid!(org) if params[:relation] == :managers
      validate_remove_user_by_guid!(org, params[:related_guid]) if params[:relation] == :users
    end

    def validate_remove_billing_manager_by_guid!(org)
      return if org.billing_managers.count > 1
      raise CloudController::Errors::ApiError.new_from_details('LastBillingManagerInOrg')
    end

    def validate_remove_manager_by_guid!(org)
      return if org.managers.count > 1
      raise CloudController::Errors::ApiError.new_from_details('LastManagerInOrg')
    end

    def validate_remove_user_by_guid!(org, user_guid)
      if org.managers.count == 1 && org.managers[0].guid == user_guid
        raise CloudController::Errors::ApiError.new_from_details('LastManagerInOrg')
      end

      if org.billing_managers.count == 1 && org.billing_managers[0].guid == user_guid
        raise CloudController::Errors::ApiError.new_from_details('LastBillingManagerInOrg')
      end

      if org.users.count == 1 && org.users[0].guid == user_guid && org.managers.count <= 1 && org.billing_managers.count <= 1
        raise CloudController::Errors::ApiError.new_from_details('LastUserInOrg')
      end
    end
  end
end
