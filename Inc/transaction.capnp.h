// Generated by Cap'n Proto compiler, DO NOT EDIT
// source: transaction.capnp

#pragma once

#include <capnp/generated-header-support.h>
#include <kj/windows-sanity.h>

#if CAPNP_VERSION != 8000
#error "Version mismatch between generated code and library headers.  You must use the same version of the Cap'n Proto compiler and library."
#endif


namespace capnp {
namespace schemas {

CAPNP_DECLARE_SCHEMA(c7c05cd4e4343fdf);
CAPNP_DECLARE_SCHEMA(a0e6a4aa33384046);
CAPNP_DECLARE_SCHEMA(85593a3f6a09e2e0);
CAPNP_DECLARE_SCHEMA(a584e4b88a131c66);

}  // namespace schemas
}  // namespace capnp


struct TransactData {
  TransactData() = delete;

  class Reader;
  class Builder;
  class Pipeline;
  struct InputData;
  struct OutputData;

  struct _capnpPrivate {
    CAPNP_DECLARE_STRUCT_HEADER(c7c05cd4e4343fdf, 0, 3)
    #if !CAPNP_LITE
    static constexpr ::capnp::_::RawBrandedSchema const* brand() { return &schema->defaultBrand; }
    #endif  // !CAPNP_LITE
  };
};

struct TransactData::InputData {
  InputData() = delete;

  class Reader;
  class Builder;
  class Pipeline;

  struct _capnpPrivate {
    CAPNP_DECLARE_STRUCT_HEADER(a0e6a4aa33384046, 1, 1)
    #if !CAPNP_LITE
    static constexpr ::capnp::_::RawBrandedSchema const* brand() { return &schema->defaultBrand; }
    #endif  // !CAPNP_LITE
  };
};

struct TransactData::OutputData {
  OutputData() = delete;

  class Reader;
  class Builder;
  class Pipeline;

  struct _capnpPrivate {
    CAPNP_DECLARE_STRUCT_HEADER(85593a3f6a09e2e0, 1, 1)
    #if !CAPNP_LITE
    static constexpr ::capnp::_::RawBrandedSchema const* brand() { return &schema->defaultBrand; }
    #endif  // !CAPNP_LITE
  };
};

struct BlockData {
  BlockData() = delete;

  class Reader;
  class Builder;
  class Pipeline;

  struct _capnpPrivate {
    CAPNP_DECLARE_STRUCT_HEADER(a584e4b88a131c66, 1, 4)
    #if !CAPNP_LITE
    static constexpr ::capnp::_::RawBrandedSchema const* brand() { return &schema->defaultBrand; }
    #endif  // !CAPNP_LITE
  };
};

// =======================================================================================

class TransactData::Reader {
public:
  typedef TransactData Reads;

  Reader() = default;
  inline explicit Reader(::capnp::_::StructReader base): _reader(base) {}

  inline ::capnp::MessageSize totalSize() const {
    return _reader.totalSize().asPublic();
  }

#if !CAPNP_LITE
  inline ::kj::StringTree toString() const {
    return ::capnp::_::structString(_reader, *_capnpPrivate::brand());
  }
#endif  // !CAPNP_LITE

  inline bool hasOutputs() const;
  inline  ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Reader getOutputs() const;

  inline bool hasInputs() const;
  inline  ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Reader getInputs() const;

  inline bool hasEcSign() const;
  inline  ::capnp::Data::Reader getEcSign() const;

private:
  ::capnp::_::StructReader _reader;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::List;
  friend class ::capnp::MessageBuilder;
  friend class ::capnp::Orphanage;
};

class TransactData::Builder {
public:
  typedef TransactData Builds;

  Builder() = delete;  // Deleted to discourage incorrect usage.
                       // You can explicitly initialize to nullptr instead.
  inline Builder(decltype(nullptr)) {}
  inline explicit Builder(::capnp::_::StructBuilder base): _builder(base) {}
  inline operator Reader() const { return Reader(_builder.asReader()); }
  inline Reader asReader() const { return *this; }

  inline ::capnp::MessageSize totalSize() const { return asReader().totalSize(); }
#if !CAPNP_LITE
  inline ::kj::StringTree toString() const { return asReader().toString(); }
#endif  // !CAPNP_LITE

  inline bool hasOutputs();
  inline  ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Builder getOutputs();
  inline void setOutputs( ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Reader value);
  inline  ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Builder initOutputs(unsigned int size);
  inline void adoptOutputs(::capnp::Orphan< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>&& value);
  inline ::capnp::Orphan< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>> disownOutputs();

  inline bool hasInputs();
  inline  ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Builder getInputs();
  inline void setInputs( ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Reader value);
  inline  ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Builder initInputs(unsigned int size);
  inline void adoptInputs(::capnp::Orphan< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>&& value);
  inline ::capnp::Orphan< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>> disownInputs();

  inline bool hasEcSign();
  inline  ::capnp::Data::Builder getEcSign();
  inline void setEcSign( ::capnp::Data::Reader value);
  inline  ::capnp::Data::Builder initEcSign(unsigned int size);
  inline void adoptEcSign(::capnp::Orphan< ::capnp::Data>&& value);
  inline ::capnp::Orphan< ::capnp::Data> disownEcSign();

private:
  ::capnp::_::StructBuilder _builder;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  friend class ::capnp::Orphanage;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
};

#if !CAPNP_LITE
class TransactData::Pipeline {
public:
  typedef TransactData Pipelines;

  inline Pipeline(decltype(nullptr)): _typeless(nullptr) {}
  inline explicit Pipeline(::capnp::AnyPointer::Pipeline&& typeless)
      : _typeless(kj::mv(typeless)) {}

private:
  ::capnp::AnyPointer::Pipeline _typeless;
  friend class ::capnp::PipelineHook;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
};
#endif  // !CAPNP_LITE

class TransactData::InputData::Reader {
public:
  typedef InputData Reads;

  Reader() = default;
  inline explicit Reader(::capnp::_::StructReader base): _reader(base) {}

  inline ::capnp::MessageSize totalSize() const {
    return _reader.totalSize().asPublic();
  }

#if !CAPNP_LITE
  inline ::kj::StringTree toString() const {
    return ::capnp::_::structString(_reader, *_capnpPrivate::brand());
  }
#endif  // !CAPNP_LITE

  inline bool hasPrevTxHash() const;
  inline  ::capnp::Data::Reader getPrevTxHash() const;

  inline  ::uint16_t getOutIdx() const;

private:
  ::capnp::_::StructReader _reader;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::List;
  friend class ::capnp::MessageBuilder;
  friend class ::capnp::Orphanage;
};

class TransactData::InputData::Builder {
public:
  typedef InputData Builds;

  Builder() = delete;  // Deleted to discourage incorrect usage.
                       // You can explicitly initialize to nullptr instead.
  inline Builder(decltype(nullptr)) {}
  inline explicit Builder(::capnp::_::StructBuilder base): _builder(base) {}
  inline operator Reader() const { return Reader(_builder.asReader()); }
  inline Reader asReader() const { return *this; }

  inline ::capnp::MessageSize totalSize() const { return asReader().totalSize(); }
#if !CAPNP_LITE
  inline ::kj::StringTree toString() const { return asReader().toString(); }
#endif  // !CAPNP_LITE

  inline bool hasPrevTxHash();
  inline  ::capnp::Data::Builder getPrevTxHash();
  inline void setPrevTxHash( ::capnp::Data::Reader value);
  inline  ::capnp::Data::Builder initPrevTxHash(unsigned int size);
  inline void adoptPrevTxHash(::capnp::Orphan< ::capnp::Data>&& value);
  inline ::capnp::Orphan< ::capnp::Data> disownPrevTxHash();

  inline  ::uint16_t getOutIdx();
  inline void setOutIdx( ::uint16_t value);

private:
  ::capnp::_::StructBuilder _builder;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  friend class ::capnp::Orphanage;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
};

#if !CAPNP_LITE
class TransactData::InputData::Pipeline {
public:
  typedef InputData Pipelines;

  inline Pipeline(decltype(nullptr)): _typeless(nullptr) {}
  inline explicit Pipeline(::capnp::AnyPointer::Pipeline&& typeless)
      : _typeless(kj::mv(typeless)) {}

private:
  ::capnp::AnyPointer::Pipeline _typeless;
  friend class ::capnp::PipelineHook;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
};
#endif  // !CAPNP_LITE

class TransactData::OutputData::Reader {
public:
  typedef OutputData Reads;

  Reader() = default;
  inline explicit Reader(::capnp::_::StructReader base): _reader(base) {}

  inline ::capnp::MessageSize totalSize() const {
    return _reader.totalSize().asPublic();
  }

#if !CAPNP_LITE
  inline ::kj::StringTree toString() const {
    return ::capnp::_::structString(_reader, *_capnpPrivate::brand());
  }
#endif  // !CAPNP_LITE

  inline  ::uint64_t getValue() const;

  inline bool hasPubKey() const;
  inline  ::capnp::Data::Reader getPubKey() const;

private:
  ::capnp::_::StructReader _reader;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::List;
  friend class ::capnp::MessageBuilder;
  friend class ::capnp::Orphanage;
};

class TransactData::OutputData::Builder {
public:
  typedef OutputData Builds;

  Builder() = delete;  // Deleted to discourage incorrect usage.
                       // You can explicitly initialize to nullptr instead.
  inline Builder(decltype(nullptr)) {}
  inline explicit Builder(::capnp::_::StructBuilder base): _builder(base) {}
  inline operator Reader() const { return Reader(_builder.asReader()); }
  inline Reader asReader() const { return *this; }

  inline ::capnp::MessageSize totalSize() const { return asReader().totalSize(); }
#if !CAPNP_LITE
  inline ::kj::StringTree toString() const { return asReader().toString(); }
#endif  // !CAPNP_LITE

  inline  ::uint64_t getValue();
  inline void setValue( ::uint64_t value);

  inline bool hasPubKey();
  inline  ::capnp::Data::Builder getPubKey();
  inline void setPubKey( ::capnp::Data::Reader value);
  inline  ::capnp::Data::Builder initPubKey(unsigned int size);
  inline void adoptPubKey(::capnp::Orphan< ::capnp::Data>&& value);
  inline ::capnp::Orphan< ::capnp::Data> disownPubKey();

private:
  ::capnp::_::StructBuilder _builder;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  friend class ::capnp::Orphanage;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
};

#if !CAPNP_LITE
class TransactData::OutputData::Pipeline {
public:
  typedef OutputData Pipelines;

  inline Pipeline(decltype(nullptr)): _typeless(nullptr) {}
  inline explicit Pipeline(::capnp::AnyPointer::Pipeline&& typeless)
      : _typeless(kj::mv(typeless)) {}

private:
  ::capnp::AnyPointer::Pipeline _typeless;
  friend class ::capnp::PipelineHook;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
};
#endif  // !CAPNP_LITE

class BlockData::Reader {
public:
  typedef BlockData Reads;

  Reader() = default;
  inline explicit Reader(::capnp::_::StructReader base): _reader(base) {}

  inline ::capnp::MessageSize totalSize() const {
    return _reader.totalSize().asPublic();
  }

#if !CAPNP_LITE
  inline ::kj::StringTree toString() const {
    return ::capnp::_::structString(_reader, *_capnpPrivate::brand());
  }
#endif  // !CAPNP_LITE

  inline bool hasPrevBlockHash() const;
  inline  ::capnp::Data::Reader getPrevBlockHash() const;

  inline bool hasMerkleRoot() const;
  inline  ::capnp::Data::Reader getMerkleRoot() const;

  inline  ::uint32_t getTimestamp() const;

  inline  ::uint32_t getDifficulty() const;

  inline bool hasNonce() const;
  inline  ::capnp::Data::Reader getNonce() const;

  inline bool hasTxs() const;
  inline  ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Reader getTxs() const;

private:
  ::capnp::_::StructReader _reader;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::List;
  friend class ::capnp::MessageBuilder;
  friend class ::capnp::Orphanage;
};

class BlockData::Builder {
public:
  typedef BlockData Builds;

  Builder() = delete;  // Deleted to discourage incorrect usage.
                       // You can explicitly initialize to nullptr instead.
  inline Builder(decltype(nullptr)) {}
  inline explicit Builder(::capnp::_::StructBuilder base): _builder(base) {}
  inline operator Reader() const { return Reader(_builder.asReader()); }
  inline Reader asReader() const { return *this; }

  inline ::capnp::MessageSize totalSize() const { return asReader().totalSize(); }
#if !CAPNP_LITE
  inline ::kj::StringTree toString() const { return asReader().toString(); }
#endif  // !CAPNP_LITE

  inline bool hasPrevBlockHash();
  inline  ::capnp::Data::Builder getPrevBlockHash();
  inline void setPrevBlockHash( ::capnp::Data::Reader value);
  inline  ::capnp::Data::Builder initPrevBlockHash(unsigned int size);
  inline void adoptPrevBlockHash(::capnp::Orphan< ::capnp::Data>&& value);
  inline ::capnp::Orphan< ::capnp::Data> disownPrevBlockHash();

  inline bool hasMerkleRoot();
  inline  ::capnp::Data::Builder getMerkleRoot();
  inline void setMerkleRoot( ::capnp::Data::Reader value);
  inline  ::capnp::Data::Builder initMerkleRoot(unsigned int size);
  inline void adoptMerkleRoot(::capnp::Orphan< ::capnp::Data>&& value);
  inline ::capnp::Orphan< ::capnp::Data> disownMerkleRoot();

  inline  ::uint32_t getTimestamp();
  inline void setTimestamp( ::uint32_t value);

  inline  ::uint32_t getDifficulty();
  inline void setDifficulty( ::uint32_t value);

  inline bool hasNonce();
  inline  ::capnp::Data::Builder getNonce();
  inline void setNonce( ::capnp::Data::Reader value);
  inline  ::capnp::Data::Builder initNonce(unsigned int size);
  inline void adoptNonce(::capnp::Orphan< ::capnp::Data>&& value);
  inline ::capnp::Orphan< ::capnp::Data> disownNonce();

  inline bool hasTxs();
  inline  ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Builder getTxs();
  inline void setTxs( ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Reader value);
  inline  ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Builder initTxs(unsigned int size);
  inline void adoptTxs(::capnp::Orphan< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>&& value);
  inline ::capnp::Orphan< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>> disownTxs();

private:
  ::capnp::_::StructBuilder _builder;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
  friend class ::capnp::Orphanage;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::_::PointerHelpers;
};

#if !CAPNP_LITE
class BlockData::Pipeline {
public:
  typedef BlockData Pipelines;

  inline Pipeline(decltype(nullptr)): _typeless(nullptr) {}
  inline explicit Pipeline(::capnp::AnyPointer::Pipeline&& typeless)
      : _typeless(kj::mv(typeless)) {}

private:
  ::capnp::AnyPointer::Pipeline _typeless;
  friend class ::capnp::PipelineHook;
  template <typename, ::capnp::Kind>
  friend struct ::capnp::ToDynamic_;
};
#endif  // !CAPNP_LITE

// =======================================================================================

inline bool TransactData::Reader::hasOutputs() const {
  return !_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline bool TransactData::Builder::hasOutputs() {
  return !_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Reader TransactData::Reader::getOutputs() const {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>::get(_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline  ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Builder TransactData::Builder::getOutputs() {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>::get(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline void TransactData::Builder::setOutputs( ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>::set(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), value);
}
inline  ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>::Builder TransactData::Builder::initOutputs(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>::init(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), size);
}
inline void TransactData::Builder::adoptOutputs(
    ::capnp::Orphan< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>::adopt(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>> TransactData::Builder::disownOutputs() {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::OutputData,  ::capnp::Kind::STRUCT>>::disown(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}

inline bool TransactData::Reader::hasInputs() const {
  return !_reader.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS).isNull();
}
inline bool TransactData::Builder::hasInputs() {
  return !_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Reader TransactData::Reader::getInputs() const {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>::get(_reader.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS));
}
inline  ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Builder TransactData::Builder::getInputs() {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>::get(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS));
}
inline void TransactData::Builder::setInputs( ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>::set(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS), value);
}
inline  ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>::Builder TransactData::Builder::initInputs(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>::init(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS), size);
}
inline void TransactData::Builder::adoptInputs(
    ::capnp::Orphan< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>::adopt(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>> TransactData::Builder::disownInputs() {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData::InputData,  ::capnp::Kind::STRUCT>>::disown(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS));
}

inline bool TransactData::Reader::hasEcSign() const {
  return !_reader.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS).isNull();
}
inline bool TransactData::Builder::hasEcSign() {
  return !_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::Data::Reader TransactData::Reader::getEcSign() const {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_reader.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS));
}
inline  ::capnp::Data::Builder TransactData::Builder::getEcSign() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS));
}
inline void TransactData::Builder::setEcSign( ::capnp::Data::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::set(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS), value);
}
inline  ::capnp::Data::Builder TransactData::Builder::initEcSign(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::init(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS), size);
}
inline void TransactData::Builder::adoptEcSign(
    ::capnp::Orphan< ::capnp::Data>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::adopt(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::Data> TransactData::Builder::disownEcSign() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::disown(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS));
}

inline bool TransactData::InputData::Reader::hasPrevTxHash() const {
  return !_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline bool TransactData::InputData::Builder::hasPrevTxHash() {
  return !_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::Data::Reader TransactData::InputData::Reader::getPrevTxHash() const {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline  ::capnp::Data::Builder TransactData::InputData::Builder::getPrevTxHash() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline void TransactData::InputData::Builder::setPrevTxHash( ::capnp::Data::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::set(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), value);
}
inline  ::capnp::Data::Builder TransactData::InputData::Builder::initPrevTxHash(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::init(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), size);
}
inline void TransactData::InputData::Builder::adoptPrevTxHash(
    ::capnp::Orphan< ::capnp::Data>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::adopt(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::Data> TransactData::InputData::Builder::disownPrevTxHash() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::disown(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}

inline  ::uint16_t TransactData::InputData::Reader::getOutIdx() const {
  return _reader.getDataField< ::uint16_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS);
}

inline  ::uint16_t TransactData::InputData::Builder::getOutIdx() {
  return _builder.getDataField< ::uint16_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS);
}
inline void TransactData::InputData::Builder::setOutIdx( ::uint16_t value) {
  _builder.setDataField< ::uint16_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS, value);
}

inline  ::uint64_t TransactData::OutputData::Reader::getValue() const {
  return _reader.getDataField< ::uint64_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS);
}

inline  ::uint64_t TransactData::OutputData::Builder::getValue() {
  return _builder.getDataField< ::uint64_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS);
}
inline void TransactData::OutputData::Builder::setValue( ::uint64_t value) {
  _builder.setDataField< ::uint64_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS, value);
}

inline bool TransactData::OutputData::Reader::hasPubKey() const {
  return !_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline bool TransactData::OutputData::Builder::hasPubKey() {
  return !_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::Data::Reader TransactData::OutputData::Reader::getPubKey() const {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline  ::capnp::Data::Builder TransactData::OutputData::Builder::getPubKey() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline void TransactData::OutputData::Builder::setPubKey( ::capnp::Data::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::set(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), value);
}
inline  ::capnp::Data::Builder TransactData::OutputData::Builder::initPubKey(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::init(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), size);
}
inline void TransactData::OutputData::Builder::adoptPubKey(
    ::capnp::Orphan< ::capnp::Data>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::adopt(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::Data> TransactData::OutputData::Builder::disownPubKey() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::disown(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}

inline bool BlockData::Reader::hasPrevBlockHash() const {
  return !_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline bool BlockData::Builder::hasPrevBlockHash() {
  return !_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::Data::Reader BlockData::Reader::getPrevBlockHash() const {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_reader.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline  ::capnp::Data::Builder BlockData::Builder::getPrevBlockHash() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}
inline void BlockData::Builder::setPrevBlockHash( ::capnp::Data::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::set(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), value);
}
inline  ::capnp::Data::Builder BlockData::Builder::initPrevBlockHash(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::init(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), size);
}
inline void BlockData::Builder::adoptPrevBlockHash(
    ::capnp::Orphan< ::capnp::Data>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::adopt(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::Data> BlockData::Builder::disownPrevBlockHash() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::disown(_builder.getPointerField(
      ::capnp::bounded<0>() * ::capnp::POINTERS));
}

inline bool BlockData::Reader::hasMerkleRoot() const {
  return !_reader.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS).isNull();
}
inline bool BlockData::Builder::hasMerkleRoot() {
  return !_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::Data::Reader BlockData::Reader::getMerkleRoot() const {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_reader.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS));
}
inline  ::capnp::Data::Builder BlockData::Builder::getMerkleRoot() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS));
}
inline void BlockData::Builder::setMerkleRoot( ::capnp::Data::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::set(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS), value);
}
inline  ::capnp::Data::Builder BlockData::Builder::initMerkleRoot(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::init(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS), size);
}
inline void BlockData::Builder::adoptMerkleRoot(
    ::capnp::Orphan< ::capnp::Data>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::adopt(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::Data> BlockData::Builder::disownMerkleRoot() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::disown(_builder.getPointerField(
      ::capnp::bounded<1>() * ::capnp::POINTERS));
}

inline  ::uint32_t BlockData::Reader::getTimestamp() const {
  return _reader.getDataField< ::uint32_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS);
}

inline  ::uint32_t BlockData::Builder::getTimestamp() {
  return _builder.getDataField< ::uint32_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS);
}
inline void BlockData::Builder::setTimestamp( ::uint32_t value) {
  _builder.setDataField< ::uint32_t>(
      ::capnp::bounded<0>() * ::capnp::ELEMENTS, value);
}

inline  ::uint32_t BlockData::Reader::getDifficulty() const {
  return _reader.getDataField< ::uint32_t>(
      ::capnp::bounded<1>() * ::capnp::ELEMENTS);
}

inline  ::uint32_t BlockData::Builder::getDifficulty() {
  return _builder.getDataField< ::uint32_t>(
      ::capnp::bounded<1>() * ::capnp::ELEMENTS);
}
inline void BlockData::Builder::setDifficulty( ::uint32_t value) {
  _builder.setDataField< ::uint32_t>(
      ::capnp::bounded<1>() * ::capnp::ELEMENTS, value);
}

inline bool BlockData::Reader::hasNonce() const {
  return !_reader.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS).isNull();
}
inline bool BlockData::Builder::hasNonce() {
  return !_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::Data::Reader BlockData::Reader::getNonce() const {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_reader.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS));
}
inline  ::capnp::Data::Builder BlockData::Builder::getNonce() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::get(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS));
}
inline void BlockData::Builder::setNonce( ::capnp::Data::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::set(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS), value);
}
inline  ::capnp::Data::Builder BlockData::Builder::initNonce(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::init(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS), size);
}
inline void BlockData::Builder::adoptNonce(
    ::capnp::Orphan< ::capnp::Data>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::Data>::adopt(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::Data> BlockData::Builder::disownNonce() {
  return ::capnp::_::PointerHelpers< ::capnp::Data>::disown(_builder.getPointerField(
      ::capnp::bounded<2>() * ::capnp::POINTERS));
}

inline bool BlockData::Reader::hasTxs() const {
  return !_reader.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS).isNull();
}
inline bool BlockData::Builder::hasTxs() {
  return !_builder.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS).isNull();
}
inline  ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Reader BlockData::Reader::getTxs() const {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>::get(_reader.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS));
}
inline  ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Builder BlockData::Builder::getTxs() {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>::get(_builder.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS));
}
inline void BlockData::Builder::setTxs( ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Reader value) {
  ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>::set(_builder.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS), value);
}
inline  ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>::Builder BlockData::Builder::initTxs(unsigned int size) {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>::init(_builder.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS), size);
}
inline void BlockData::Builder::adoptTxs(
    ::capnp::Orphan< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>&& value) {
  ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>::adopt(_builder.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS), kj::mv(value));
}
inline ::capnp::Orphan< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>> BlockData::Builder::disownTxs() {
  return ::capnp::_::PointerHelpers< ::capnp::List< ::TransactData,  ::capnp::Kind::STRUCT>>::disown(_builder.getPointerField(
      ::capnp::bounded<3>() * ::capnp::POINTERS));
}

