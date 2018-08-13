require 'spec_helper'

module VCAP::CloudController
  RSpec.describe OrganizationAccess, type: :access do
    let(:queryer) { instance_spy(Permissions::Queryer) }

    subject(:access) { OrganizationAccess.new(Security::AccessContext.new(queryer)) }
    let(:user) { VCAP::CloudController::User.make }
    let(:org) { VCAP::CloudController::Organization.make }
    let(:object) { org }
    let(:flag) { FeatureFlag.make(name: 'user_org_creation', enabled: false) }

    before do
      flag.save
    end
