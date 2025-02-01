// Generated by the protocol buffer compiler.  DO NOT EDIT!
// NO CHECKED-IN PROTOBUF GENCODE
// source: leechgrpc.proto
// Protobuf C++ Version: 5.29.2

#ifndef leechgrpc_2eproto_2epb_2eh
#define leechgrpc_2eproto_2epb_2eh

#include <limits>
#include <string>
#include <type_traits>
#include <utility>

#include "google/protobuf/runtime_version.h"
#if PROTOBUF_VERSION != 5029002
#error "Protobuf C++ gencode is built with an incompatible version of"
#error "Protobuf C++ headers/runtime. See"
#error "https://protobuf.dev/support/cross-version-runtime-guarantee/#cpp"
#endif
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/arenastring.h"
#include "google/protobuf/generated_message_tctable_decl.h"
#include "google/protobuf/generated_message_util.h"
#include "google/protobuf/metadata_lite.h"
#include "google/protobuf/generated_message_reflection.h"
#include "google/protobuf/message.h"
#include "google/protobuf/message_lite.h"
#include "google/protobuf/repeated_field.h"  // IWYU pragma: export
#include "google/protobuf/extension_set.h"  // IWYU pragma: export
#include "google/protobuf/unknown_field_set.h"
// @@protoc_insertion_point(includes)

// Must be included last.
#include "google/protobuf/port_def.inc"

#define PROTOBUF_INTERNAL_EXPORT_leechgrpc_2eproto

namespace google {
namespace protobuf {
namespace internal {
template <typename T>
::absl::string_view GetAnyMessageName();
}  // namespace internal
}  // namespace protobuf
}  // namespace google

// Internal implementation detail -- do not use these members.
struct TableStruct_leechgrpc_2eproto {
  static const ::uint32_t offsets[];
};
extern const ::google::protobuf::internal::DescriptorTable
    descriptor_table_leechgrpc_2eproto;
namespace leechrpc {
class SubmitCommandRequest;
struct SubmitCommandRequestDefaultTypeInternal;
extern SubmitCommandRequestDefaultTypeInternal _SubmitCommandRequest_default_instance_;
class SubmitCommandResponse;
struct SubmitCommandResponseDefaultTypeInternal;
extern SubmitCommandResponseDefaultTypeInternal _SubmitCommandResponse_default_instance_;
}  // namespace leechrpc
namespace google {
namespace protobuf {
}  // namespace protobuf
}  // namespace google

namespace leechrpc {

// ===================================================================


// -------------------------------------------------------------------

class SubmitCommandResponse final : public ::google::protobuf::Message
/* @@protoc_insertion_point(class_definition:leechrpc.SubmitCommandResponse) */ {
 public:
  inline SubmitCommandResponse() : SubmitCommandResponse(nullptr) {}
  ~SubmitCommandResponse() PROTOBUF_FINAL;

#if defined(PROTOBUF_CUSTOM_VTABLE)
  void operator delete(SubmitCommandResponse* msg, std::destroying_delete_t) {
    SharedDtor(*msg);
    ::google::protobuf::internal::SizedDelete(msg, sizeof(SubmitCommandResponse));
  }
#endif

  template <typename = void>
  explicit PROTOBUF_CONSTEXPR SubmitCommandResponse(
      ::google::protobuf::internal::ConstantInitialized);

  inline SubmitCommandResponse(const SubmitCommandResponse& from) : SubmitCommandResponse(nullptr, from) {}
  inline SubmitCommandResponse(SubmitCommandResponse&& from) noexcept
      : SubmitCommandResponse(nullptr, std::move(from)) {}
  inline SubmitCommandResponse& operator=(const SubmitCommandResponse& from) {
    CopyFrom(from);
    return *this;
  }
  inline SubmitCommandResponse& operator=(SubmitCommandResponse&& from) noexcept {
    if (this == &from) return *this;
    if (::google::protobuf::internal::CanMoveWithInternalSwap(GetArena(), from.GetArena())) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance);
  }
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields()
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.mutable_unknown_fields<::google::protobuf::UnknownFieldSet>();
  }

  static const ::google::protobuf::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::google::protobuf::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::google::protobuf::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const SubmitCommandResponse& default_instance() {
    return *internal_default_instance();
  }
  static inline const SubmitCommandResponse* internal_default_instance() {
    return reinterpret_cast<const SubmitCommandResponse*>(
        &_SubmitCommandResponse_default_instance_);
  }
  static constexpr int kIndexInFileMessages = 1;
  friend void swap(SubmitCommandResponse& a, SubmitCommandResponse& b) { a.Swap(&b); }
  inline void Swap(SubmitCommandResponse* other) {
    if (other == this) return;
    if (::google::protobuf::internal::CanUseInternalSwap(GetArena(), other->GetArena())) {
      InternalSwap(other);
    } else {
      ::google::protobuf::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(SubmitCommandResponse* other) {
    if (other == this) return;
    ABSL_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  SubmitCommandResponse* New(::google::protobuf::Arena* arena = nullptr) const {
    return ::google::protobuf::Message::DefaultConstruct<SubmitCommandResponse>(arena);
  }
  using ::google::protobuf::Message::CopyFrom;
  void CopyFrom(const SubmitCommandResponse& from);
  using ::google::protobuf::Message::MergeFrom;
  void MergeFrom(const SubmitCommandResponse& from) { SubmitCommandResponse::MergeImpl(*this, from); }

  private:
  static void MergeImpl(
      ::google::protobuf::MessageLite& to_msg,
      const ::google::protobuf::MessageLite& from_msg);

  public:
  bool IsInitialized() const {
    return true;
  }
  ABSL_ATTRIBUTE_REINITIALIZES void Clear() PROTOBUF_FINAL;
  #if defined(PROTOBUF_CUSTOM_VTABLE)
  private:
  static ::size_t ByteSizeLong(const ::google::protobuf::MessageLite& msg);
  static ::uint8_t* _InternalSerialize(
      const MessageLite& msg, ::uint8_t* target,
      ::google::protobuf::io::EpsCopyOutputStream* stream);

  public:
  ::size_t ByteSizeLong() const { return ByteSizeLong(*this); }
  ::uint8_t* _InternalSerialize(
      ::uint8_t* target,
      ::google::protobuf::io::EpsCopyOutputStream* stream) const {
    return _InternalSerialize(*this, target, stream);
  }
  #else   // PROTOBUF_CUSTOM_VTABLE
  ::size_t ByteSizeLong() const final;
  ::uint8_t* _InternalSerialize(
      ::uint8_t* target,
      ::google::protobuf::io::EpsCopyOutputStream* stream) const final;
  #endif  // PROTOBUF_CUSTOM_VTABLE
  int GetCachedSize() const { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::google::protobuf::Arena* arena);
  static void SharedDtor(MessageLite& self);
  void InternalSwap(SubmitCommandResponse* other);
 private:
  template <typename T>
  friend ::absl::string_view(
      ::google::protobuf::internal::GetAnyMessageName)();
  static ::absl::string_view FullMessageName() { return "leechrpc.SubmitCommandResponse"; }

 protected:
  explicit SubmitCommandResponse(::google::protobuf::Arena* arena);
  SubmitCommandResponse(::google::protobuf::Arena* arena, const SubmitCommandResponse& from);
  SubmitCommandResponse(::google::protobuf::Arena* arena, SubmitCommandResponse&& from) noexcept
      : SubmitCommandResponse(arena) {
    *this = ::std::move(from);
  }
  const ::google::protobuf::internal::ClassData* GetClassData() const PROTOBUF_FINAL;
  static void* PlacementNew_(const void*, void* mem,
                             ::google::protobuf::Arena* arena);
  static constexpr auto InternalNewImpl_();
  static const ::google::protobuf::internal::ClassDataFull _class_data_;

 public:
  ::google::protobuf::Metadata GetMetadata() const;
  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------
  enum : int {
    kPbOutFieldNumber = 1,
  };
  // bytes pbOut = 1;
  void clear_pbout() ;
  const std::string& pbout() const;
  template <typename Arg_ = const std::string&, typename... Args_>
  void set_pbout(Arg_&& arg, Args_... args);
  std::string* mutable_pbout();
  PROTOBUF_NODISCARD std::string* release_pbout();
  void set_allocated_pbout(std::string* value);

  private:
  const std::string& _internal_pbout() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_pbout(
      const std::string& value);
  std::string* _internal_mutable_pbout();

  public:
  // @@protoc_insertion_point(class_scope:leechrpc.SubmitCommandResponse)
 private:
  class _Internal;
  friend class ::google::protobuf::internal::TcParser;
  static const ::google::protobuf::internal::TcParseTable<
      0, 1, 0,
      0, 2>
      _table_;

  friend class ::google::protobuf::MessageLite;
  friend class ::google::protobuf::Arena;
  template <typename T>
  friend class ::google::protobuf::Arena::InternalHelper;
  using InternalArenaConstructable_ = void;
  using DestructorSkippable_ = void;
  struct Impl_ {
    inline explicit constexpr Impl_(
        ::google::protobuf::internal::ConstantInitialized) noexcept;
    inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                          ::google::protobuf::Arena* arena);
    inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                          ::google::protobuf::Arena* arena, const Impl_& from,
                          const SubmitCommandResponse& from_msg);
    ::google::protobuf::internal::ArenaStringPtr pbout_;
    ::google::protobuf::internal::CachedSize _cached_size_;
    PROTOBUF_TSAN_DECLARE_MEMBER
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_leechgrpc_2eproto;
};
// -------------------------------------------------------------------

class SubmitCommandRequest final : public ::google::protobuf::Message
/* @@protoc_insertion_point(class_definition:leechrpc.SubmitCommandRequest) */ {
 public:
  inline SubmitCommandRequest() : SubmitCommandRequest(nullptr) {}
  ~SubmitCommandRequest() PROTOBUF_FINAL;

#if defined(PROTOBUF_CUSTOM_VTABLE)
  void operator delete(SubmitCommandRequest* msg, std::destroying_delete_t) {
    SharedDtor(*msg);
    ::google::protobuf::internal::SizedDelete(msg, sizeof(SubmitCommandRequest));
  }
#endif

  template <typename = void>
  explicit PROTOBUF_CONSTEXPR SubmitCommandRequest(
      ::google::protobuf::internal::ConstantInitialized);

  inline SubmitCommandRequest(const SubmitCommandRequest& from) : SubmitCommandRequest(nullptr, from) {}
  inline SubmitCommandRequest(SubmitCommandRequest&& from) noexcept
      : SubmitCommandRequest(nullptr, std::move(from)) {}
  inline SubmitCommandRequest& operator=(const SubmitCommandRequest& from) {
    CopyFrom(from);
    return *this;
  }
  inline SubmitCommandRequest& operator=(SubmitCommandRequest&& from) noexcept {
    if (this == &from) return *this;
    if (::google::protobuf::internal::CanMoveWithInternalSwap(GetArena(), from.GetArena())) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.unknown_fields<::google::protobuf::UnknownFieldSet>(::google::protobuf::UnknownFieldSet::default_instance);
  }
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields()
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return _internal_metadata_.mutable_unknown_fields<::google::protobuf::UnknownFieldSet>();
  }

  static const ::google::protobuf::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::google::protobuf::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::google::protobuf::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const SubmitCommandRequest& default_instance() {
    return *internal_default_instance();
  }
  static inline const SubmitCommandRequest* internal_default_instance() {
    return reinterpret_cast<const SubmitCommandRequest*>(
        &_SubmitCommandRequest_default_instance_);
  }
  static constexpr int kIndexInFileMessages = 0;
  friend void swap(SubmitCommandRequest& a, SubmitCommandRequest& b) { a.Swap(&b); }
  inline void Swap(SubmitCommandRequest* other) {
    if (other == this) return;
    if (::google::protobuf::internal::CanUseInternalSwap(GetArena(), other->GetArena())) {
      InternalSwap(other);
    } else {
      ::google::protobuf::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(SubmitCommandRequest* other) {
    if (other == this) return;
    ABSL_DCHECK(GetArena() == other->GetArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  SubmitCommandRequest* New(::google::protobuf::Arena* arena = nullptr) const {
    return ::google::protobuf::Message::DefaultConstruct<SubmitCommandRequest>(arena);
  }
  using ::google::protobuf::Message::CopyFrom;
  void CopyFrom(const SubmitCommandRequest& from);
  using ::google::protobuf::Message::MergeFrom;
  void MergeFrom(const SubmitCommandRequest& from) { SubmitCommandRequest::MergeImpl(*this, from); }

  private:
  static void MergeImpl(
      ::google::protobuf::MessageLite& to_msg,
      const ::google::protobuf::MessageLite& from_msg);

  public:
  bool IsInitialized() const {
    return true;
  }
  ABSL_ATTRIBUTE_REINITIALIZES void Clear() PROTOBUF_FINAL;
  #if defined(PROTOBUF_CUSTOM_VTABLE)
  private:
  static ::size_t ByteSizeLong(const ::google::protobuf::MessageLite& msg);
  static ::uint8_t* _InternalSerialize(
      const MessageLite& msg, ::uint8_t* target,
      ::google::protobuf::io::EpsCopyOutputStream* stream);

  public:
  ::size_t ByteSizeLong() const { return ByteSizeLong(*this); }
  ::uint8_t* _InternalSerialize(
      ::uint8_t* target,
      ::google::protobuf::io::EpsCopyOutputStream* stream) const {
    return _InternalSerialize(*this, target, stream);
  }
  #else   // PROTOBUF_CUSTOM_VTABLE
  ::size_t ByteSizeLong() const final;
  ::uint8_t* _InternalSerialize(
      ::uint8_t* target,
      ::google::protobuf::io::EpsCopyOutputStream* stream) const final;
  #endif  // PROTOBUF_CUSTOM_VTABLE
  int GetCachedSize() const { return _impl_._cached_size_.Get(); }

  private:
  void SharedCtor(::google::protobuf::Arena* arena);
  static void SharedDtor(MessageLite& self);
  void InternalSwap(SubmitCommandRequest* other);
 private:
  template <typename T>
  friend ::absl::string_view(
      ::google::protobuf::internal::GetAnyMessageName)();
  static ::absl::string_view FullMessageName() { return "leechrpc.SubmitCommandRequest"; }

 protected:
  explicit SubmitCommandRequest(::google::protobuf::Arena* arena);
  SubmitCommandRequest(::google::protobuf::Arena* arena, const SubmitCommandRequest& from);
  SubmitCommandRequest(::google::protobuf::Arena* arena, SubmitCommandRequest&& from) noexcept
      : SubmitCommandRequest(arena) {
    *this = ::std::move(from);
  }
  const ::google::protobuf::internal::ClassData* GetClassData() const PROTOBUF_FINAL;
  static void* PlacementNew_(const void*, void* mem,
                             ::google::protobuf::Arena* arena);
  static constexpr auto InternalNewImpl_();
  static const ::google::protobuf::internal::ClassDataFull _class_data_;

 public:
  ::google::protobuf::Metadata GetMetadata() const;
  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------
  enum : int {
    kPbInFieldNumber = 1,
  };
  // bytes pbIn = 1;
  void clear_pbin() ;
  const std::string& pbin() const;
  template <typename Arg_ = const std::string&, typename... Args_>
  void set_pbin(Arg_&& arg, Args_... args);
  std::string* mutable_pbin();
  PROTOBUF_NODISCARD std::string* release_pbin();
  void set_allocated_pbin(std::string* value);

  private:
  const std::string& _internal_pbin() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_pbin(
      const std::string& value);
  std::string* _internal_mutable_pbin();

  public:
  // @@protoc_insertion_point(class_scope:leechrpc.SubmitCommandRequest)
 private:
  class _Internal;
  friend class ::google::protobuf::internal::TcParser;
  static const ::google::protobuf::internal::TcParseTable<
      0, 1, 0,
      0, 2>
      _table_;

  friend class ::google::protobuf::MessageLite;
  friend class ::google::protobuf::Arena;
  template <typename T>
  friend class ::google::protobuf::Arena::InternalHelper;
  using InternalArenaConstructable_ = void;
  using DestructorSkippable_ = void;
  struct Impl_ {
    inline explicit constexpr Impl_(
        ::google::protobuf::internal::ConstantInitialized) noexcept;
    inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                          ::google::protobuf::Arena* arena);
    inline explicit Impl_(::google::protobuf::internal::InternalVisibility visibility,
                          ::google::protobuf::Arena* arena, const Impl_& from,
                          const SubmitCommandRequest& from_msg);
    ::google::protobuf::internal::ArenaStringPtr pbin_;
    ::google::protobuf::internal::CachedSize _cached_size_;
    PROTOBUF_TSAN_DECLARE_MEMBER
  };
  union { Impl_ _impl_; };
  friend struct ::TableStruct_leechgrpc_2eproto;
};

// ===================================================================




// ===================================================================


#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// -------------------------------------------------------------------

// SubmitCommandRequest

// bytes pbIn = 1;
inline void SubmitCommandRequest::clear_pbin() {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbin_.ClearToEmpty();
}
inline const std::string& SubmitCommandRequest::pbin() const
    ABSL_ATTRIBUTE_LIFETIME_BOUND {
  // @@protoc_insertion_point(field_get:leechrpc.SubmitCommandRequest.pbIn)
  return _internal_pbin();
}
template <typename Arg_, typename... Args_>
inline PROTOBUF_ALWAYS_INLINE void SubmitCommandRequest::set_pbin(Arg_&& arg,
                                                     Args_... args) {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbin_.SetBytes(static_cast<Arg_&&>(arg), args..., GetArena());
  // @@protoc_insertion_point(field_set:leechrpc.SubmitCommandRequest.pbIn)
}
inline std::string* SubmitCommandRequest::mutable_pbin() ABSL_ATTRIBUTE_LIFETIME_BOUND {
  std::string* _s = _internal_mutable_pbin();
  // @@protoc_insertion_point(field_mutable:leechrpc.SubmitCommandRequest.pbIn)
  return _s;
}
inline const std::string& SubmitCommandRequest::_internal_pbin() const {
  ::google::protobuf::internal::TSanRead(&_impl_);
  return _impl_.pbin_.Get();
}
inline void SubmitCommandRequest::_internal_set_pbin(const std::string& value) {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbin_.Set(value, GetArena());
}
inline std::string* SubmitCommandRequest::_internal_mutable_pbin() {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  return _impl_.pbin_.Mutable( GetArena());
}
inline std::string* SubmitCommandRequest::release_pbin() {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  // @@protoc_insertion_point(field_release:leechrpc.SubmitCommandRequest.pbIn)
  return _impl_.pbin_.Release();
}
inline void SubmitCommandRequest::set_allocated_pbin(std::string* value) {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbin_.SetAllocated(value, GetArena());
  if (::google::protobuf::internal::DebugHardenForceCopyDefaultString() && _impl_.pbin_.IsDefault()) {
    _impl_.pbin_.Set("", GetArena());
  }
  // @@protoc_insertion_point(field_set_allocated:leechrpc.SubmitCommandRequest.pbIn)
}

// -------------------------------------------------------------------

// SubmitCommandResponse

// bytes pbOut = 1;
inline void SubmitCommandResponse::clear_pbout() {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbout_.ClearToEmpty();
}
inline const std::string& SubmitCommandResponse::pbout() const
    ABSL_ATTRIBUTE_LIFETIME_BOUND {
  // @@protoc_insertion_point(field_get:leechrpc.SubmitCommandResponse.pbOut)
  return _internal_pbout();
}
template <typename Arg_, typename... Args_>
inline PROTOBUF_ALWAYS_INLINE void SubmitCommandResponse::set_pbout(Arg_&& arg,
                                                     Args_... args) {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbout_.SetBytes(static_cast<Arg_&&>(arg), args..., GetArena());
  // @@protoc_insertion_point(field_set:leechrpc.SubmitCommandResponse.pbOut)
}
inline std::string* SubmitCommandResponse::mutable_pbout() ABSL_ATTRIBUTE_LIFETIME_BOUND {
  std::string* _s = _internal_mutable_pbout();
  // @@protoc_insertion_point(field_mutable:leechrpc.SubmitCommandResponse.pbOut)
  return _s;
}
inline const std::string& SubmitCommandResponse::_internal_pbout() const {
  ::google::protobuf::internal::TSanRead(&_impl_);
  return _impl_.pbout_.Get();
}
inline void SubmitCommandResponse::_internal_set_pbout(const std::string& value) {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbout_.Set(value, GetArena());
}
inline std::string* SubmitCommandResponse::_internal_mutable_pbout() {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  return _impl_.pbout_.Mutable( GetArena());
}
inline std::string* SubmitCommandResponse::release_pbout() {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  // @@protoc_insertion_point(field_release:leechrpc.SubmitCommandResponse.pbOut)
  return _impl_.pbout_.Release();
}
inline void SubmitCommandResponse::set_allocated_pbout(std::string* value) {
  ::google::protobuf::internal::TSanWrite(&_impl_);
  _impl_.pbout_.SetAllocated(value, GetArena());
  if (::google::protobuf::internal::DebugHardenForceCopyDefaultString() && _impl_.pbout_.IsDefault()) {
    _impl_.pbout_.Set("", GetArena());
  }
  // @@protoc_insertion_point(field_set_allocated:leechrpc.SubmitCommandResponse.pbOut)
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)
}  // namespace leechrpc


// @@protoc_insertion_point(global_scope)

#include "google/protobuf/port_undef.inc"

#endif  // leechgrpc_2eproto_2epb_2eh
