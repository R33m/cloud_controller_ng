odule VCAP::CloudController
  class RouteAccess < BaseAccess

  if VCAP::CloudController::SecurityContext.self.current_user_location=="Office"
    def create?(route, params=nil)
      can_write_to_route(route, true)
    end

    def read_for_update?(route, params=nil)
      can_write_to_route(route, false)
    end

    def update?(route, params=nil)
      can_write_to_route(route, false)
    end

    def delete?(route)
      can_write_to_route(route, false)
    end

    def reserved?(_)
      logged_in?
    end

    def reserved_with_token?(_)
      context.queryer.can_write_globally? || has_read_scope?
    end

    def can_remove_related_object?(object, params=nil)
      read_for_update?(object, params)
    end

    def read_related_object_for_update?(object, params=nil)
      read_for_update?(object, params)
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


    private

    def can_write_to_route(route, is_create=false)
      return true if context.queryer.can_write_globally?
      return false if route.in_suspended_org?
      return false if route.wildcard_host? && route.domain.shared?
      FeatureFlag.raise_unless_enabled!(:route_creation) if is_create
      context.queryer.can_write_to_space?(route.space.guid)
    end
  elsif VCAP::CloudController::SecurityContext.self.current_user_location=="public"
     def create?(route, params=nil)
       return false
     end

     def read_for_update?(route, params=nil)
       return false
     end

     def update?(route, params=nil)
       return false
     end

     def delete?(route)
       return false
     end

     def reserved?(_)
       return false
     end

     def reserved_with_token?(_)
       return false
     end

     def can_remove_related_object?(object, params=nil)
       return false
     end

     def read_related_object_for_update?(object, params=nil)
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


     private

     def can_write_to_route(route, is_create=false)
       return false
  end

    public

    def read?(route)
     context.queryer.can_read_route?(route.space.guid, route.space.organization.guid)
   end

    def index?(_, params=nil)
      # This can return true because the index endpoints filter objects based on user visibilities
      true
    end

    def read_with_token?(_)
      admin_user? || admin_read_only_user? || has_read_scope? || global_auditor?
    end

    def index_with_token?(_)
      # This can return true because the index endpoints filter objects based on user visibilities
      true
    end
  end
end
