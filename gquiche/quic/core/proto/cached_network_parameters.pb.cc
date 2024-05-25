// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: cached_network_parameters.proto

#include "cached_network_parameters.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
namespace quic {
class CachedNetworkParametersDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<CachedNetworkParameters> _instance;
} _CachedNetworkParameters_default_instance_;
}  // namespace quic
static void InitDefaultsscc_info_CachedNetworkParameters_cached_5fnetwork_5fparameters_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::quic::_CachedNetworkParameters_default_instance_;
    new (ptr) ::quic::CachedNetworkParameters();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::quic::CachedNetworkParameters::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_CachedNetworkParameters_cached_5fnetwork_5fparameters_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_CachedNetworkParameters_cached_5fnetwork_5fparameters_2eproto}, {}};

namespace quic {
bool CachedNetworkParameters_PreviousConnectionState_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
      return true;
    default:
      return false;
  }
}

static ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<std::string> CachedNetworkParameters_PreviousConnectionState_strings[2] = {};

static const char CachedNetworkParameters_PreviousConnectionState_names[] =
  "CONGESTION_AVOIDANCE"
  "SLOW_START";

static const ::PROTOBUF_NAMESPACE_ID::internal::EnumEntry CachedNetworkParameters_PreviousConnectionState_entries[] = {
  { {CachedNetworkParameters_PreviousConnectionState_names + 0, 20}, 1 },
  { {CachedNetworkParameters_PreviousConnectionState_names + 20, 10}, 0 },
};

static const int CachedNetworkParameters_PreviousConnectionState_entries_by_number[] = {
  1, // 0 -> SLOW_START
  0, // 1 -> CONGESTION_AVOIDANCE
};

const std::string& CachedNetworkParameters_PreviousConnectionState_Name(
    CachedNetworkParameters_PreviousConnectionState value) {
  static const bool dummy =
      ::PROTOBUF_NAMESPACE_ID::internal::InitializeEnumStrings(
          CachedNetworkParameters_PreviousConnectionState_entries,
          CachedNetworkParameters_PreviousConnectionState_entries_by_number,
          2, CachedNetworkParameters_PreviousConnectionState_strings);
  (void) dummy;
  int idx = ::PROTOBUF_NAMESPACE_ID::internal::LookUpEnumName(
      CachedNetworkParameters_PreviousConnectionState_entries,
      CachedNetworkParameters_PreviousConnectionState_entries_by_number,
      2, value);
  return idx == -1 ? ::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString() :
                     CachedNetworkParameters_PreviousConnectionState_strings[idx].get();
}
bool CachedNetworkParameters_PreviousConnectionState_Parse(
    const std::string& name, CachedNetworkParameters_PreviousConnectionState* value) {
  int int_value;
  bool success = ::PROTOBUF_NAMESPACE_ID::internal::LookUpEnumValue(
      CachedNetworkParameters_PreviousConnectionState_entries, 2, name, &int_value);
  if (success) {
    *value = static_cast<CachedNetworkParameters_PreviousConnectionState>(int_value);
  }
  return success;
}
#if (__cplusplus < 201703) && (!defined(_MSC_VER) || _MSC_VER >= 1900)
constexpr CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::SLOW_START;
constexpr CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::CONGESTION_AVOIDANCE;
constexpr CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::PreviousConnectionState_MIN;
constexpr CachedNetworkParameters_PreviousConnectionState CachedNetworkParameters::PreviousConnectionState_MAX;
constexpr int CachedNetworkParameters::PreviousConnectionState_ARRAYSIZE;
#endif  // (__cplusplus < 201703) && (!defined(_MSC_VER) || _MSC_VER >= 1900)

// ===================================================================

void CachedNetworkParameters::InitAsDefaultInstance() {
}
class CachedNetworkParameters::_Internal {
 public:
  using HasBits = decltype(std::declval<CachedNetworkParameters>()._has_bits_);
  static void set_has_serving_region(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static void set_has_bandwidth_estimate_bytes_per_second(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
  static void set_has_max_bandwidth_estimate_bytes_per_second(HasBits* has_bits) {
    (*has_bits)[0] |= 16u;
  }
  static void set_has_max_bandwidth_timestamp_seconds(HasBits* has_bits) {
    (*has_bits)[0] |= 32u;
  }
  static void set_has_min_rtt_ms(HasBits* has_bits) {
    (*has_bits)[0] |= 4u;
  }
  static void set_has_previous_connection_state(HasBits* has_bits) {
    (*has_bits)[0] |= 8u;
  }
  static void set_has_timestamp(HasBits* has_bits) {
    (*has_bits)[0] |= 64u;
  }
};

CachedNetworkParameters::CachedNetworkParameters(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:quic.CachedNetworkParameters)
}
CachedNetworkParameters::CachedNetworkParameters(const CachedNetworkParameters& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(),
      _has_bits_(from._has_bits_) {
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  serving_region_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (from._internal_has_serving_region()) {
    serving_region_.SetLite(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_serving_region(),
      GetArena());
  }
  ::memcpy(&bandwidth_estimate_bytes_per_second_, &from.bandwidth_estimate_bytes_per_second_,
    static_cast<size_t>(reinterpret_cast<char*>(&timestamp_) -
    reinterpret_cast<char*>(&bandwidth_estimate_bytes_per_second_)) + sizeof(timestamp_));
  // @@protoc_insertion_point(copy_constructor:quic.CachedNetworkParameters)
}

void CachedNetworkParameters::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_CachedNetworkParameters_cached_5fnetwork_5fparameters_2eproto.base);
  serving_region_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  ::memset(&bandwidth_estimate_bytes_per_second_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&timestamp_) -
      reinterpret_cast<char*>(&bandwidth_estimate_bytes_per_second_)) + sizeof(timestamp_));
}

CachedNetworkParameters::~CachedNetworkParameters() {
  // @@protoc_insertion_point(destructor:quic.CachedNetworkParameters)
  SharedDtor();
  _internal_metadata_.Delete<std::string>();
}

void CachedNetworkParameters::SharedDtor() {
  GOOGLE_DCHECK(GetArena() == nullptr);
  serving_region_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void CachedNetworkParameters::ArenaDtor(void* object) {
  CachedNetworkParameters* _this = reinterpret_cast< CachedNetworkParameters* >(object);
  (void)_this;
}
void CachedNetworkParameters::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void CachedNetworkParameters::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const CachedNetworkParameters& CachedNetworkParameters::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_CachedNetworkParameters_cached_5fnetwork_5fparameters_2eproto.base);
  return *internal_default_instance();
}


void CachedNetworkParameters::Clear() {
// @@protoc_insertion_point(message_clear_start:quic.CachedNetworkParameters)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    serving_region_.ClearNonDefaultToEmpty();
  }
  if (cached_has_bits & 0x0000007eu) {
    ::memset(&bandwidth_estimate_bytes_per_second_, 0, static_cast<size_t>(
        reinterpret_cast<char*>(&timestamp_) -
        reinterpret_cast<char*>(&bandwidth_estimate_bytes_per_second_)) + sizeof(timestamp_));
  }
  _has_bits_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* CachedNetworkParameters::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  ::PROTOBUF_NAMESPACE_ID::Arena* arena = GetArena(); (void)arena;
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // optional string serving_region = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_serving_region();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // optional int32 bandwidth_estimate_bytes_per_second = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 16)) {
          _Internal::set_has_bandwidth_estimate_bytes_per_second(&has_bits);
          bandwidth_estimate_bytes_per_second_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // optional int32 min_rtt_ms = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 24)) {
          _Internal::set_has_min_rtt_ms(&has_bits);
          min_rtt_ms_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // optional int32 previous_connection_state = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 32)) {
          _Internal::set_has_previous_connection_state(&has_bits);
          previous_connection_state_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // optional int32 max_bandwidth_estimate_bytes_per_second = 5;
      case 5:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 40)) {
          _Internal::set_has_max_bandwidth_estimate_bytes_per_second(&has_bits);
          max_bandwidth_estimate_bytes_per_second_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // optional int64 max_bandwidth_timestamp_seconds = 6;
      case 6:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 48)) {
          _Internal::set_has_max_bandwidth_timestamp_seconds(&has_bits);
          max_bandwidth_timestamp_seconds_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // optional int64 timestamp = 7;
      case 7:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 56)) {
          _Internal::set_has_timestamp(&has_bits);
          timestamp_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->SetLastTag(tag);
          goto success;
        }
        ptr = UnknownFieldParse(tag,
            _internal_metadata_.mutable_unknown_fields<std::string>(),
            ptr, ctx);
        CHK_(ptr != nullptr);
        continue;
      }
    }  // switch
  }  // while
success:
  _has_bits_.Or(has_bits);
  return ptr;
failure:
  ptr = nullptr;
  goto success;
#undef CHK_
}

::PROTOBUF_NAMESPACE_ID::uint8* CachedNetworkParameters::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:quic.CachedNetworkParameters)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  // optional string serving_region = 1;
  if (cached_has_bits & 0x00000001u) {
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_serving_region(), target);
  }

  // optional int32 bandwidth_estimate_bytes_per_second = 2;
  if (cached_has_bits & 0x00000002u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(2, this->_internal_bandwidth_estimate_bytes_per_second(), target);
  }

  // optional int32 min_rtt_ms = 3;
  if (cached_has_bits & 0x00000004u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(3, this->_internal_min_rtt_ms(), target);
  }

  // optional int32 previous_connection_state = 4;
  if (cached_has_bits & 0x00000008u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(4, this->_internal_previous_connection_state(), target);
  }

  // optional int32 max_bandwidth_estimate_bytes_per_second = 5;
  if (cached_has_bits & 0x00000010u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt32ToArray(5, this->_internal_max_bandwidth_estimate_bytes_per_second(), target);
  }

  // optional int64 max_bandwidth_timestamp_seconds = 6;
  if (cached_has_bits & 0x00000020u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt64ToArray(6, this->_internal_max_bandwidth_timestamp_seconds(), target);
  }

  // optional int64 timestamp = 7;
  if (cached_has_bits & 0x00000040u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt64ToArray(7, this->_internal_timestamp(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:quic.CachedNetworkParameters)
  return target;
}

size_t CachedNetworkParameters::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:quic.CachedNetworkParameters)
  size_t total_size = 0;

  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 0x0000007fu) {
    // optional string serving_region = 1;
    if (cached_has_bits & 0x00000001u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
          this->_internal_serving_region());
    }

    // optional int32 bandwidth_estimate_bytes_per_second = 2;
    if (cached_has_bits & 0x00000002u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
          this->_internal_bandwidth_estimate_bytes_per_second());
    }

    // optional int32 min_rtt_ms = 3;
    if (cached_has_bits & 0x00000004u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
          this->_internal_min_rtt_ms());
    }

    // optional int32 previous_connection_state = 4;
    if (cached_has_bits & 0x00000008u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
          this->_internal_previous_connection_state());
    }

    // optional int32 max_bandwidth_estimate_bytes_per_second = 5;
    if (cached_has_bits & 0x00000010u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int32Size(
          this->_internal_max_bandwidth_estimate_bytes_per_second());
    }

    // optional int64 max_bandwidth_timestamp_seconds = 6;
    if (cached_has_bits & 0x00000020u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int64Size(
          this->_internal_max_bandwidth_timestamp_seconds());
    }

    // optional int64 timestamp = 7;
    if (cached_has_bits & 0x00000040u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int64Size(
          this->_internal_timestamp());
    }

  }
  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void CachedNetworkParameters::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::PROTOBUF_NAMESPACE_ID::internal::DownCast<const CachedNetworkParameters*>(
      &from));
}

void CachedNetworkParameters::MergeFrom(const CachedNetworkParameters& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:quic.CachedNetworkParameters)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._has_bits_[0];
  if (cached_has_bits & 0x0000007fu) {
    if (cached_has_bits & 0x00000001u) {
      _internal_set_serving_region(from._internal_serving_region());
    }
    if (cached_has_bits & 0x00000002u) {
      bandwidth_estimate_bytes_per_second_ = from.bandwidth_estimate_bytes_per_second_;
    }
    if (cached_has_bits & 0x00000004u) {
      min_rtt_ms_ = from.min_rtt_ms_;
    }
    if (cached_has_bits & 0x00000008u) {
      previous_connection_state_ = from.previous_connection_state_;
    }
    if (cached_has_bits & 0x00000010u) {
      max_bandwidth_estimate_bytes_per_second_ = from.max_bandwidth_estimate_bytes_per_second_;
    }
    if (cached_has_bits & 0x00000020u) {
      max_bandwidth_timestamp_seconds_ = from.max_bandwidth_timestamp_seconds_;
    }
    if (cached_has_bits & 0x00000040u) {
      timestamp_ = from.timestamp_;
    }
    _has_bits_[0] |= cached_has_bits;
  }
}

void CachedNetworkParameters::CopyFrom(const CachedNetworkParameters& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:quic.CachedNetworkParameters)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool CachedNetworkParameters::IsInitialized() const {
  return true;
}

void CachedNetworkParameters::InternalSwap(CachedNetworkParameters* other) {
  using std::swap;
  _internal_metadata_.Swap<std::string>(&other->_internal_metadata_);
  swap(_has_bits_[0], other->_has_bits_[0]);
  serving_region_.Swap(&other->serving_region_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(CachedNetworkParameters, timestamp_)
      + sizeof(CachedNetworkParameters::timestamp_)
      - PROTOBUF_FIELD_OFFSET(CachedNetworkParameters, bandwidth_estimate_bytes_per_second_)>(
          reinterpret_cast<char*>(&bandwidth_estimate_bytes_per_second_),
          reinterpret_cast<char*>(&other->bandwidth_estimate_bytes_per_second_));
}

std::string CachedNetworkParameters::GetTypeName() const {
  return "quic.CachedNetworkParameters";
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace quic
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::quic::CachedNetworkParameters* Arena::CreateMaybeMessage< ::quic::CachedNetworkParameters >(Arena* arena) {
  return Arena::CreateMessageInternal< ::quic::CachedNetworkParameters >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
