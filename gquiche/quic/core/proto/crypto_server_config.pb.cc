// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: crypto_server_config.proto

#include "crypto_server_config.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
extern PROTOBUF_INTERNAL_EXPORT_crypto_5fserver_5fconfig_2eproto ::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_QuicServerConfigProtobuf_PrivateKey_crypto_5fserver_5fconfig_2eproto;
namespace quic {
class QuicServerConfigProtobuf_PrivateKeyDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<QuicServerConfigProtobuf_PrivateKey> _instance;
} _QuicServerConfigProtobuf_PrivateKey_default_instance_;
class QuicServerConfigProtobufDefaultTypeInternal {
 public:
  ::PROTOBUF_NAMESPACE_ID::internal::ExplicitlyConstructed<QuicServerConfigProtobuf> _instance;
} _QuicServerConfigProtobuf_default_instance_;
}  // namespace quic
static void InitDefaultsscc_info_QuicServerConfigProtobuf_crypto_5fserver_5fconfig_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::quic::_QuicServerConfigProtobuf_default_instance_;
    new (ptr) ::quic::QuicServerConfigProtobuf();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::quic::QuicServerConfigProtobuf::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<1> scc_info_QuicServerConfigProtobuf_crypto_5fserver_5fconfig_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 1, 0, InitDefaultsscc_info_QuicServerConfigProtobuf_crypto_5fserver_5fconfig_2eproto}, {
      &scc_info_QuicServerConfigProtobuf_PrivateKey_crypto_5fserver_5fconfig_2eproto.base,}};

static void InitDefaultsscc_info_QuicServerConfigProtobuf_PrivateKey_crypto_5fserver_5fconfig_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::quic::_QuicServerConfigProtobuf_PrivateKey_default_instance_;
    new (ptr) ::quic::QuicServerConfigProtobuf_PrivateKey();
    ::PROTOBUF_NAMESPACE_ID::internal::OnShutdownDestroyMessage(ptr);
  }
  ::quic::QuicServerConfigProtobuf_PrivateKey::InitAsDefaultInstance();
}

::PROTOBUF_NAMESPACE_ID::internal::SCCInfo<0> scc_info_QuicServerConfigProtobuf_PrivateKey_crypto_5fserver_5fconfig_2eproto =
    {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_QuicServerConfigProtobuf_PrivateKey_crypto_5fserver_5fconfig_2eproto}, {}};

namespace quic {

// ===================================================================

void QuicServerConfigProtobuf_PrivateKey::InitAsDefaultInstance() {
}
class QuicServerConfigProtobuf_PrivateKey::_Internal {
 public:
  using HasBits = decltype(std::declval<QuicServerConfigProtobuf_PrivateKey>()._has_bits_);
  static void set_has_tag(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
  static void set_has_private_key(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static bool MissingRequiredFields(const HasBits& has_bits) {
    return ((has_bits[0] & 0x00000003) ^ 0x00000003) != 0;
  }
};

QuicServerConfigProtobuf_PrivateKey::QuicServerConfigProtobuf_PrivateKey(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:quic.QuicServerConfigProtobuf.PrivateKey)
}
QuicServerConfigProtobuf_PrivateKey::QuicServerConfigProtobuf_PrivateKey(const QuicServerConfigProtobuf_PrivateKey& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(),
      _has_bits_(from._has_bits_) {
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  private_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (from._internal_has_private_key()) {
    private_key_.SetLite(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_private_key(),
      GetArena());
  }
  tag_ = from.tag_;
  // @@protoc_insertion_point(copy_constructor:quic.QuicServerConfigProtobuf.PrivateKey)
}

void QuicServerConfigProtobuf_PrivateKey::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_QuicServerConfigProtobuf_PrivateKey_crypto_5fserver_5fconfig_2eproto.base);
  private_key_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  tag_ = 0u;
}

QuicServerConfigProtobuf_PrivateKey::~QuicServerConfigProtobuf_PrivateKey() {
  // @@protoc_insertion_point(destructor:quic.QuicServerConfigProtobuf.PrivateKey)
  SharedDtor();
  _internal_metadata_.Delete<std::string>();
}

void QuicServerConfigProtobuf_PrivateKey::SharedDtor() {
  GOOGLE_DCHECK(GetArena() == nullptr);
  private_key_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void QuicServerConfigProtobuf_PrivateKey::ArenaDtor(void* object) {
  QuicServerConfigProtobuf_PrivateKey* _this = reinterpret_cast< QuicServerConfigProtobuf_PrivateKey* >(object);
  (void)_this;
}
void QuicServerConfigProtobuf_PrivateKey::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void QuicServerConfigProtobuf_PrivateKey::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const QuicServerConfigProtobuf_PrivateKey& QuicServerConfigProtobuf_PrivateKey::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_QuicServerConfigProtobuf_PrivateKey_crypto_5fserver_5fconfig_2eproto.base);
  return *internal_default_instance();
}


void QuicServerConfigProtobuf_PrivateKey::Clear() {
// @@protoc_insertion_point(message_clear_start:quic.QuicServerConfigProtobuf.PrivateKey)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    private_key_.ClearNonDefaultToEmpty();
  }
  tag_ = 0u;
  _has_bits_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* QuicServerConfigProtobuf_PrivateKey::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  ::PROTOBUF_NAMESPACE_ID::Arena* arena = GetArena(); (void)arena;
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // required uint32 tag = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 8)) {
          _Internal::set_has_tag(&has_bits);
          tag_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint32(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // required bytes private_key = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          auto str = _internal_mutable_private_key();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
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

::PROTOBUF_NAMESPACE_ID::uint8* QuicServerConfigProtobuf_PrivateKey::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:quic.QuicServerConfigProtobuf.PrivateKey)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  // required uint32 tag = 1;
  if (cached_has_bits & 0x00000002u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteUInt32ToArray(1, this->_internal_tag(), target);
  }

  // required bytes private_key = 2;
  if (cached_has_bits & 0x00000001u) {
    target = stream->WriteBytesMaybeAliased(
        2, this->_internal_private_key(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:quic.QuicServerConfigProtobuf.PrivateKey)
  return target;
}

size_t QuicServerConfigProtobuf_PrivateKey::RequiredFieldsByteSizeFallback() const {
// @@protoc_insertion_point(required_fields_byte_size_fallback_start:quic.QuicServerConfigProtobuf.PrivateKey)
  size_t total_size = 0;

  if (_internal_has_private_key()) {
    // required bytes private_key = 2;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_private_key());
  }

  if (_internal_has_tag()) {
    // required uint32 tag = 1;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::UInt32Size(
        this->_internal_tag());
  }

  return total_size;
}
size_t QuicServerConfigProtobuf_PrivateKey::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:quic.QuicServerConfigProtobuf.PrivateKey)
  size_t total_size = 0;

  if (((_has_bits_[0] & 0x00000003) ^ 0x00000003) == 0) {  // All required fields are present.
    // required bytes private_key = 2;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_private_key());

    // required uint32 tag = 1;
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::UInt32Size(
        this->_internal_tag());

  } else {
    total_size += RequiredFieldsByteSizeFallback();
  }
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void QuicServerConfigProtobuf_PrivateKey::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::PROTOBUF_NAMESPACE_ID::internal::DownCast<const QuicServerConfigProtobuf_PrivateKey*>(
      &from));
}

void QuicServerConfigProtobuf_PrivateKey::MergeFrom(const QuicServerConfigProtobuf_PrivateKey& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:quic.QuicServerConfigProtobuf.PrivateKey)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._has_bits_[0];
  if (cached_has_bits & 0x00000003u) {
    if (cached_has_bits & 0x00000001u) {
      _internal_set_private_key(from._internal_private_key());
    }
    if (cached_has_bits & 0x00000002u) {
      tag_ = from.tag_;
    }
    _has_bits_[0] |= cached_has_bits;
  }
}

void QuicServerConfigProtobuf_PrivateKey::CopyFrom(const QuicServerConfigProtobuf_PrivateKey& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:quic.QuicServerConfigProtobuf.PrivateKey)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool QuicServerConfigProtobuf_PrivateKey::IsInitialized() const {
  if (_Internal::MissingRequiredFields(_has_bits_)) return false;
  return true;
}

void QuicServerConfigProtobuf_PrivateKey::InternalSwap(QuicServerConfigProtobuf_PrivateKey* other) {
  using std::swap;
  _internal_metadata_.Swap<std::string>(&other->_internal_metadata_);
  swap(_has_bits_[0], other->_has_bits_[0]);
  private_key_.Swap(&other->private_key_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  swap(tag_, other->tag_);
}

std::string QuicServerConfigProtobuf_PrivateKey::GetTypeName() const {
  return "quic.QuicServerConfigProtobuf.PrivateKey";
}


// ===================================================================

void QuicServerConfigProtobuf::InitAsDefaultInstance() {
}
class QuicServerConfigProtobuf::_Internal {
 public:
  using HasBits = decltype(std::declval<QuicServerConfigProtobuf>()._has_bits_);
  static void set_has_config(HasBits* has_bits) {
    (*has_bits)[0] |= 1u;
  }
  static void set_has_primary_time(HasBits* has_bits) {
    (*has_bits)[0] |= 2u;
  }
  static void set_has_priority(HasBits* has_bits) {
    (*has_bits)[0] |= 4u;
  }
  static bool MissingRequiredFields(const HasBits& has_bits) {
    return ((has_bits[0] & 0x00000001) ^ 0x00000001) != 0;
  }
};

QuicServerConfigProtobuf::QuicServerConfigProtobuf(::PROTOBUF_NAMESPACE_ID::Arena* arena)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(arena),
  key_(arena) {
  SharedCtor();
  RegisterArenaDtor(arena);
  // @@protoc_insertion_point(arena_constructor:quic.QuicServerConfigProtobuf)
}
QuicServerConfigProtobuf::QuicServerConfigProtobuf(const QuicServerConfigProtobuf& from)
  : ::PROTOBUF_NAMESPACE_ID::MessageLite(),
      _has_bits_(from._has_bits_),
      key_(from.key_) {
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  config_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  if (from._internal_has_config()) {
    config_.SetLite(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), from._internal_config(),
      GetArena());
  }
  ::memcpy(&primary_time_, &from.primary_time_,
    static_cast<size_t>(reinterpret_cast<char*>(&priority_) -
    reinterpret_cast<char*>(&primary_time_)) + sizeof(priority_));
  // @@protoc_insertion_point(copy_constructor:quic.QuicServerConfigProtobuf)
}

void QuicServerConfigProtobuf::SharedCtor() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&scc_info_QuicServerConfigProtobuf_crypto_5fserver_5fconfig_2eproto.base);
  config_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  ::memset(&primary_time_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&priority_) -
      reinterpret_cast<char*>(&primary_time_)) + sizeof(priority_));
}

QuicServerConfigProtobuf::~QuicServerConfigProtobuf() {
  // @@protoc_insertion_point(destructor:quic.QuicServerConfigProtobuf)
  SharedDtor();
  _internal_metadata_.Delete<std::string>();
}

void QuicServerConfigProtobuf::SharedDtor() {
  GOOGLE_DCHECK(GetArena() == nullptr);
  config_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void QuicServerConfigProtobuf::ArenaDtor(void* object) {
  QuicServerConfigProtobuf* _this = reinterpret_cast< QuicServerConfigProtobuf* >(object);
  (void)_this;
}
void QuicServerConfigProtobuf::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void QuicServerConfigProtobuf::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const QuicServerConfigProtobuf& QuicServerConfigProtobuf::default_instance() {
  ::PROTOBUF_NAMESPACE_ID::internal::InitSCC(&::scc_info_QuicServerConfigProtobuf_crypto_5fserver_5fconfig_2eproto.base);
  return *internal_default_instance();
}


void QuicServerConfigProtobuf::Clear() {
// @@protoc_insertion_point(message_clear_start:quic.QuicServerConfigProtobuf)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  key_.Clear();
  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 0x00000001u) {
    config_.ClearNonDefaultToEmpty();
  }
  if (cached_has_bits & 0x00000006u) {
    ::memset(&primary_time_, 0, static_cast<size_t>(
        reinterpret_cast<char*>(&priority_) -
        reinterpret_cast<char*>(&primary_time_)) + sizeof(priority_));
  }
  _has_bits_.Clear();
  _internal_metadata_.Clear<std::string>();
}

const char* QuicServerConfigProtobuf::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  _Internal::HasBits has_bits{};
  ::PROTOBUF_NAMESPACE_ID::Arena* arena = GetArena(); (void)arena;
  while (!ctx->Done(&ptr)) {
    ::PROTOBUF_NAMESPACE_ID::uint32 tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    CHK_(ptr);
    switch (tag >> 3) {
      // required bytes config = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 10)) {
          auto str = _internal_mutable_config();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // repeated .quic.QuicServerConfigProtobuf.PrivateKey key = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 18)) {
          ptr -= 1;
          do {
            ptr += 1;
            ptr = ctx->ParseMessage(_internal_add_key(), ptr);
            CHK_(ptr);
            if (!ctx->DataAvailable(ptr)) break;
          } while (::PROTOBUF_NAMESPACE_ID::internal::ExpectTag<18>(ptr));
        } else goto handle_unusual;
        continue;
      // optional int64 primary_time = 3;
      case 3:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 24)) {
          _Internal::set_has_primary_time(&has_bits);
          primary_time_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else goto handle_unusual;
        continue;
      // optional uint64 priority = 4;
      case 4:
        if (PROTOBUF_PREDICT_TRUE(static_cast<::PROTOBUF_NAMESPACE_ID::uint8>(tag) == 32)) {
          _Internal::set_has_priority(&has_bits);
          priority_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
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

::PROTOBUF_NAMESPACE_ID::uint8* QuicServerConfigProtobuf::_InternalSerialize(
    ::PROTOBUF_NAMESPACE_ID::uint8* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:quic.QuicServerConfigProtobuf)
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  // required bytes config = 1;
  if (cached_has_bits & 0x00000001u) {
    target = stream->WriteBytesMaybeAliased(
        1, this->_internal_config(), target);
  }

  // repeated .quic.QuicServerConfigProtobuf.PrivateKey key = 2;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->_internal_key_size()); i < n; i++) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::
      InternalWriteMessage(2, this->_internal_key(i), target, stream);
  }

  // optional int64 primary_time = 3;
  if (cached_has_bits & 0x00000002u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt64ToArray(3, this->_internal_primary_time(), target);
  }

  // optional uint64 priority = 4;
  if (cached_has_bits & 0x00000004u) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteUInt64ToArray(4, this->_internal_priority(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = stream->WriteRaw(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).data(),
        static_cast<int>(_internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:quic.QuicServerConfigProtobuf)
  return target;
}

size_t QuicServerConfigProtobuf::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:quic.QuicServerConfigProtobuf)
  size_t total_size = 0;

  // required bytes config = 1;
  if (_internal_has_config()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::BytesSize(
        this->_internal_config());
  }
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .quic.QuicServerConfigProtobuf.PrivateKey key = 2;
  total_size += 1UL * this->_internal_key_size();
  for (const auto& msg : this->key_) {
    total_size +=
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::MessageSize(msg);
  }

  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 0x00000006u) {
    // optional int64 primary_time = 3;
    if (cached_has_bits & 0x00000002u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int64Size(
          this->_internal_primary_time());
    }

    // optional uint64 priority = 4;
    if (cached_has_bits & 0x00000004u) {
      total_size += 1 +
        ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::UInt64Size(
          this->_internal_priority());
    }

  }
  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    total_size += _internal_metadata_.unknown_fields<std::string>(::PROTOBUF_NAMESPACE_ID::internal::GetEmptyString).size();
  }
  int cached_size = ::PROTOBUF_NAMESPACE_ID::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void QuicServerConfigProtobuf::CheckTypeAndMergeFrom(
    const ::PROTOBUF_NAMESPACE_ID::MessageLite& from) {
  MergeFrom(*::PROTOBUF_NAMESPACE_ID::internal::DownCast<const QuicServerConfigProtobuf*>(
      &from));
}

void QuicServerConfigProtobuf::MergeFrom(const QuicServerConfigProtobuf& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:quic.QuicServerConfigProtobuf)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom<std::string>(from._internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  key_.MergeFrom(from.key_);
  cached_has_bits = from._has_bits_[0];
  if (cached_has_bits & 0x00000007u) {
    if (cached_has_bits & 0x00000001u) {
      _internal_set_config(from._internal_config());
    }
    if (cached_has_bits & 0x00000002u) {
      primary_time_ = from.primary_time_;
    }
    if (cached_has_bits & 0x00000004u) {
      priority_ = from.priority_;
    }
    _has_bits_[0] |= cached_has_bits;
  }
}

void QuicServerConfigProtobuf::CopyFrom(const QuicServerConfigProtobuf& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:quic.QuicServerConfigProtobuf)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool QuicServerConfigProtobuf::IsInitialized() const {
  if (_Internal::MissingRequiredFields(_has_bits_)) return false;
  if (!::PROTOBUF_NAMESPACE_ID::internal::AllAreInitialized(key_)) return false;
  return true;
}

void QuicServerConfigProtobuf::InternalSwap(QuicServerConfigProtobuf* other) {
  using std::swap;
  _internal_metadata_.Swap<std::string>(&other->_internal_metadata_);
  swap(_has_bits_[0], other->_has_bits_[0]);
  key_.InternalSwap(&other->key_);
  config_.Swap(&other->config_, &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArena());
  ::PROTOBUF_NAMESPACE_ID::internal::memswap<
      PROTOBUF_FIELD_OFFSET(QuicServerConfigProtobuf, priority_)
      + sizeof(QuicServerConfigProtobuf::priority_)
      - PROTOBUF_FIELD_OFFSET(QuicServerConfigProtobuf, primary_time_)>(
          reinterpret_cast<char*>(&primary_time_),
          reinterpret_cast<char*>(&other->primary_time_));
}

std::string QuicServerConfigProtobuf::GetTypeName() const {
  return "quic.QuicServerConfigProtobuf";
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace quic
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::quic::QuicServerConfigProtobuf_PrivateKey* Arena::CreateMaybeMessage< ::quic::QuicServerConfigProtobuf_PrivateKey >(Arena* arena) {
  return Arena::CreateMessageInternal< ::quic::QuicServerConfigProtobuf_PrivateKey >(arena);
}
template<> PROTOBUF_NOINLINE ::quic::QuicServerConfigProtobuf* Arena::CreateMaybeMessage< ::quic::QuicServerConfigProtobuf >(Arena* arena) {
  return Arena::CreateMessageInternal< ::quic::QuicServerConfigProtobuf >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
