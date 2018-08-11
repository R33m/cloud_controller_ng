# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: egress.proto

# See README.md in this directory for the commands used to generate this file

require 'google/protobuf'

require 'logcache/v2/envelope_pb'
require 'google/api/annotations_pb'

Google::Protobuf::DescriptorPool.generated_pool.build do
  add_message "logcache.v1.ReadRequest" do
    optional :source_id, :string, 1
    optional :start_time, :int64, 2
    optional :end_time, :int64, 3
    optional :limit, :int64, 4
    repeated :envelope_types, :enum, 5, "logcache.v1.EnvelopeType"
    optional :descending, :bool, 6
  end
  add_message "logcache.v1.ReadResponse" do
    optional :envelopes, :message, 1, "loggregator.v2.EnvelopeBatch"
  end
  add_message "logcache.v1.MetaRequest" do
    optional :local_only, :bool, 1
  end
  add_message "logcache.v1.MetaResponse" do
    map :meta, :string, :message, 1, "logcache.v1.MetaInfo"
  end
  add_message "logcache.v1.MetaInfo" do
    optional :count, :int64, 1
    optional :expired, :int64, 2
    optional :oldest_timestamp, :int64, 3
    optional :newest_timestamp, :int64, 4
  end
  add_enum "logcache.v1.EnvelopeType" do
    value :ANY, 0
    value :LOG, 1
    value :COUNTER, 2
    value :GAUGE, 3
    value :TIMER, 4
    value :EVENT, 5
  end
end

module Logcache
  module V1
    ReadRequest = Google::Protobuf::DescriptorPool.generated_pool.lookup("logcache.v1.ReadRequest").msgclass
    ReadResponse = Google::Protobuf::DescriptorPool.generated_pool.lookup("logcache.v1.ReadResponse").msgclass
    MetaRequest = Google::Protobuf::DescriptorPool.generated_pool.lookup("logcache.v1.MetaRequest").msgclass
    MetaResponse = Google::Protobuf::DescriptorPool.generated_pool.lookup("logcache.v1.MetaResponse").msgclass
    MetaInfo = Google::Protobuf::DescriptorPool.generated_pool.lookup("logcache.v1.MetaInfo").msgclass
    EnvelopeType = Google::Protobuf::DescriptorPool.generated_pool.lookup("logcache.v1.EnvelopeType").enummodule
  end
end
