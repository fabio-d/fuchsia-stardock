// WARNING: This file is machine generated by fidlgen.

#include <fuchsia/hardware/usb/peripheral/block/llcpp/fidl.h>
#include <memory>

namespace llcpp {

namespace fuchsia {
namespace hardware {
namespace usb {
namespace peripheral {
namespace block {

namespace {

[[maybe_unused]]
constexpr uint64_t kDevice_EnableWritebackCache_GenOrdinal = 0x2b47735200000000lu;
extern "C" const fidl_type_t fuchsia_hardware_usb_peripheral_block_DeviceEnableWritebackCacheResponseTable;
[[maybe_unused]]
constexpr uint64_t kDevice_DisableWritebackCache_GenOrdinal = 0x2e4207e900000000lu;
extern "C" const fidl_type_t fuchsia_hardware_usb_peripheral_block_DeviceDisableWritebackCacheResponseTable;
[[maybe_unused]]
constexpr uint64_t kDevice_SetWritebackCacheReported_GenOrdinal = 0x340bd79400000000lu;
extern "C" const fidl_type_t fuchsia_hardware_usb_peripheral_block_DeviceSetWritebackCacheReportedRequestTable;
extern "C" const fidl_type_t fuchsia_hardware_usb_peripheral_block_DeviceSetWritebackCacheReportedResponseTable;

}  // namespace
template <>
Device::ResultOf::EnableWritebackCache_Impl<Device::EnableWritebackCacheResponse>::EnableWritebackCache_Impl(zx::unowned_channel _client_end) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<EnableWritebackCacheRequest>();
  ::fidl::internal::AlignedBuffer<_kWriteAllocSize> _write_bytes_inlined;
  auto& _write_bytes_array = _write_bytes_inlined;
  uint8_t* _write_bytes = _write_bytes_array.view().data();
  memset(_write_bytes, 0, EnableWritebackCacheRequest::PrimarySize);
  ::fidl::BytePart _request_bytes(_write_bytes, _kWriteAllocSize, sizeof(EnableWritebackCacheRequest));
  ::fidl::DecodedMessage<EnableWritebackCacheRequest> _decoded_request(std::move(_request_bytes));
  Super::SetResult(
      Device::InPlace::EnableWritebackCache(std::move(_client_end), Super::response_buffer()));
}

Device::ResultOf::EnableWritebackCache Device::SyncClient::EnableWritebackCache() {
  return ResultOf::EnableWritebackCache(zx::unowned_channel(this->channel_));
}

Device::ResultOf::EnableWritebackCache Device::Call::EnableWritebackCache(zx::unowned_channel _client_end) {
  return ResultOf::EnableWritebackCache(std::move(_client_end));
}

template <>
Device::UnownedResultOf::EnableWritebackCache_Impl<Device::EnableWritebackCacheResponse>::EnableWritebackCache_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer) {
  FIDL_ALIGNDECL uint8_t _write_bytes[sizeof(EnableWritebackCacheRequest)] = {};
  ::fidl::BytePart _request_buffer(_write_bytes, sizeof(_write_bytes));
  memset(_request_buffer.data(), 0, EnableWritebackCacheRequest::PrimarySize);
  _request_buffer.set_actual(sizeof(EnableWritebackCacheRequest));
  ::fidl::DecodedMessage<EnableWritebackCacheRequest> _decoded_request(std::move(_request_buffer));
  Super::SetResult(
      Device::InPlace::EnableWritebackCache(std::move(_client_end), std::move(_response_buffer)));
}

Device::UnownedResultOf::EnableWritebackCache Device::SyncClient::EnableWritebackCache(::fidl::BytePart _response_buffer) {
  return UnownedResultOf::EnableWritebackCache(zx::unowned_channel(this->channel_), std::move(_response_buffer));
}

Device::UnownedResultOf::EnableWritebackCache Device::Call::EnableWritebackCache(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer) {
  return UnownedResultOf::EnableWritebackCache(std::move(_client_end), std::move(_response_buffer));
}

zx_status_t Device::SyncClient::EnableWritebackCache_Deprecated(int32_t* out_status) {
  return Device::Call::EnableWritebackCache_Deprecated(zx::unowned_channel(this->channel_), out_status);
}

zx_status_t Device::Call::EnableWritebackCache_Deprecated(zx::unowned_channel _client_end, int32_t* out_status) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<EnableWritebackCacheRequest>();
  FIDL_ALIGNDECL uint8_t _write_bytes[_kWriteAllocSize] = {};
  auto& _request = *reinterpret_cast<EnableWritebackCacheRequest*>(_write_bytes);
  _request._hdr.ordinal = kDevice_EnableWritebackCache_GenOrdinal;
  ::fidl::BytePart _request_bytes(_write_bytes, _kWriteAllocSize, sizeof(EnableWritebackCacheRequest));
  ::fidl::DecodedMessage<EnableWritebackCacheRequest> _decoded_request(std::move(_request_bytes));
  auto _encode_request_result = ::fidl::Encode(std::move(_decoded_request));
  if (_encode_request_result.status != ZX_OK) {
    return _encode_request_result.status;
  }
  constexpr uint32_t _kReadAllocSize = ::fidl::internal::ClampedMessageSize<EnableWritebackCacheResponse>();
  FIDL_ALIGNDECL uint8_t _read_bytes[_kReadAllocSize];
  ::fidl::BytePart _response_bytes(_read_bytes, _kReadAllocSize);
  auto _call_result = ::fidl::Call<EnableWritebackCacheRequest, EnableWritebackCacheResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(_response_bytes));
  if (_call_result.status != ZX_OK) {
    return _call_result.status;
  }
  auto _decode_result = ::fidl::Decode(std::move(_call_result.message));
  if (_decode_result.status != ZX_OK) {
    return _decode_result.status;
  }
  auto& _response = *_decode_result.message.message();
  *out_status = std::move(_response.status);
  return ZX_OK;
}

::fidl::DecodeResult<Device::EnableWritebackCacheResponse> Device::SyncClient::EnableWritebackCache_Deprecated(::fidl::BytePart _response_buffer, int32_t* out_status) {
  return Device::Call::EnableWritebackCache_Deprecated(zx::unowned_channel(this->channel_), std::move(_response_buffer), out_status);
}

::fidl::DecodeResult<Device::EnableWritebackCacheResponse> Device::Call::EnableWritebackCache_Deprecated(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer, int32_t* out_status) {
  FIDL_ALIGNDECL uint8_t _write_bytes[sizeof(EnableWritebackCacheRequest)] = {};
  ::fidl::BytePart _request_buffer(_write_bytes, sizeof(_write_bytes));
  auto& _request = *reinterpret_cast<EnableWritebackCacheRequest*>(_request_buffer.data());
  _request._hdr.ordinal = kDevice_EnableWritebackCache_GenOrdinal;
  _request_buffer.set_actual(sizeof(EnableWritebackCacheRequest));
  ::fidl::DecodedMessage<EnableWritebackCacheRequest> _decoded_request(std::move(_request_buffer));
  auto _encode_request_result = ::fidl::Encode(std::move(_decoded_request));
  if (_encode_request_result.status != ZX_OK) {
    return ::fidl::DecodeResult<EnableWritebackCacheResponse>(_encode_request_result.status, _encode_request_result.error);
  }
  auto _call_result = ::fidl::Call<EnableWritebackCacheRequest, EnableWritebackCacheResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(_response_buffer));
  if (_call_result.status != ZX_OK) {
    return ::fidl::DecodeResult<EnableWritebackCacheResponse>(_call_result.status, _call_result.error);
  }
  auto _decode_result = ::fidl::Decode(std::move(_call_result.message));
  if (_decode_result.status != ZX_OK) {
    return _decode_result;
  }
  auto& _response = *_decode_result.message.message();
  *out_status = std::move(_response.status);
  return _decode_result;
}

::fidl::DecodeResult<Device::EnableWritebackCacheResponse> Device::InPlace::EnableWritebackCache(zx::unowned_channel _client_end, ::fidl::BytePart response_buffer) {
  constexpr uint32_t _write_num_bytes = sizeof(EnableWritebackCacheRequest);
  ::fidl::internal::AlignedBuffer<_write_num_bytes> _write_bytes;
  ::fidl::BytePart _request_buffer = _write_bytes.view();
  _request_buffer.set_actual(_write_num_bytes);
  ::fidl::DecodedMessage<EnableWritebackCacheRequest> params(std::move(_request_buffer));
  params.message()->_hdr = {};
  params.message()->_hdr.ordinal = kDevice_EnableWritebackCache_GenOrdinal;
  auto _encode_request_result = ::fidl::Encode(std::move(params));
  if (_encode_request_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Device::EnableWritebackCacheResponse>::FromFailure(
        std::move(_encode_request_result));
  }
  auto _call_result = ::fidl::Call<EnableWritebackCacheRequest, EnableWritebackCacheResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(response_buffer));
  if (_call_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Device::EnableWritebackCacheResponse>::FromFailure(
        std::move(_call_result));
  }
  return ::fidl::Decode(std::move(_call_result.message));
}

template <>
Device::ResultOf::DisableWritebackCache_Impl<Device::DisableWritebackCacheResponse>::DisableWritebackCache_Impl(zx::unowned_channel _client_end) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<DisableWritebackCacheRequest>();
  ::fidl::internal::AlignedBuffer<_kWriteAllocSize> _write_bytes_inlined;
  auto& _write_bytes_array = _write_bytes_inlined;
  uint8_t* _write_bytes = _write_bytes_array.view().data();
  memset(_write_bytes, 0, DisableWritebackCacheRequest::PrimarySize);
  ::fidl::BytePart _request_bytes(_write_bytes, _kWriteAllocSize, sizeof(DisableWritebackCacheRequest));
  ::fidl::DecodedMessage<DisableWritebackCacheRequest> _decoded_request(std::move(_request_bytes));
  Super::SetResult(
      Device::InPlace::DisableWritebackCache(std::move(_client_end), Super::response_buffer()));
}

Device::ResultOf::DisableWritebackCache Device::SyncClient::DisableWritebackCache() {
  return ResultOf::DisableWritebackCache(zx::unowned_channel(this->channel_));
}

Device::ResultOf::DisableWritebackCache Device::Call::DisableWritebackCache(zx::unowned_channel _client_end) {
  return ResultOf::DisableWritebackCache(std::move(_client_end));
}

template <>
Device::UnownedResultOf::DisableWritebackCache_Impl<Device::DisableWritebackCacheResponse>::DisableWritebackCache_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer) {
  FIDL_ALIGNDECL uint8_t _write_bytes[sizeof(DisableWritebackCacheRequest)] = {};
  ::fidl::BytePart _request_buffer(_write_bytes, sizeof(_write_bytes));
  memset(_request_buffer.data(), 0, DisableWritebackCacheRequest::PrimarySize);
  _request_buffer.set_actual(sizeof(DisableWritebackCacheRequest));
  ::fidl::DecodedMessage<DisableWritebackCacheRequest> _decoded_request(std::move(_request_buffer));
  Super::SetResult(
      Device::InPlace::DisableWritebackCache(std::move(_client_end), std::move(_response_buffer)));
}

Device::UnownedResultOf::DisableWritebackCache Device::SyncClient::DisableWritebackCache(::fidl::BytePart _response_buffer) {
  return UnownedResultOf::DisableWritebackCache(zx::unowned_channel(this->channel_), std::move(_response_buffer));
}

Device::UnownedResultOf::DisableWritebackCache Device::Call::DisableWritebackCache(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer) {
  return UnownedResultOf::DisableWritebackCache(std::move(_client_end), std::move(_response_buffer));
}

zx_status_t Device::SyncClient::DisableWritebackCache_Deprecated(int32_t* out_status) {
  return Device::Call::DisableWritebackCache_Deprecated(zx::unowned_channel(this->channel_), out_status);
}

zx_status_t Device::Call::DisableWritebackCache_Deprecated(zx::unowned_channel _client_end, int32_t* out_status) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<DisableWritebackCacheRequest>();
  FIDL_ALIGNDECL uint8_t _write_bytes[_kWriteAllocSize] = {};
  auto& _request = *reinterpret_cast<DisableWritebackCacheRequest*>(_write_bytes);
  _request._hdr.ordinal = kDevice_DisableWritebackCache_GenOrdinal;
  ::fidl::BytePart _request_bytes(_write_bytes, _kWriteAllocSize, sizeof(DisableWritebackCacheRequest));
  ::fidl::DecodedMessage<DisableWritebackCacheRequest> _decoded_request(std::move(_request_bytes));
  auto _encode_request_result = ::fidl::Encode(std::move(_decoded_request));
  if (_encode_request_result.status != ZX_OK) {
    return _encode_request_result.status;
  }
  constexpr uint32_t _kReadAllocSize = ::fidl::internal::ClampedMessageSize<DisableWritebackCacheResponse>();
  FIDL_ALIGNDECL uint8_t _read_bytes[_kReadAllocSize];
  ::fidl::BytePart _response_bytes(_read_bytes, _kReadAllocSize);
  auto _call_result = ::fidl::Call<DisableWritebackCacheRequest, DisableWritebackCacheResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(_response_bytes));
  if (_call_result.status != ZX_OK) {
    return _call_result.status;
  }
  auto _decode_result = ::fidl::Decode(std::move(_call_result.message));
  if (_decode_result.status != ZX_OK) {
    return _decode_result.status;
  }
  auto& _response = *_decode_result.message.message();
  *out_status = std::move(_response.status);
  return ZX_OK;
}

::fidl::DecodeResult<Device::DisableWritebackCacheResponse> Device::SyncClient::DisableWritebackCache_Deprecated(::fidl::BytePart _response_buffer, int32_t* out_status) {
  return Device::Call::DisableWritebackCache_Deprecated(zx::unowned_channel(this->channel_), std::move(_response_buffer), out_status);
}

::fidl::DecodeResult<Device::DisableWritebackCacheResponse> Device::Call::DisableWritebackCache_Deprecated(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer, int32_t* out_status) {
  FIDL_ALIGNDECL uint8_t _write_bytes[sizeof(DisableWritebackCacheRequest)] = {};
  ::fidl::BytePart _request_buffer(_write_bytes, sizeof(_write_bytes));
  auto& _request = *reinterpret_cast<DisableWritebackCacheRequest*>(_request_buffer.data());
  _request._hdr.ordinal = kDevice_DisableWritebackCache_GenOrdinal;
  _request_buffer.set_actual(sizeof(DisableWritebackCacheRequest));
  ::fidl::DecodedMessage<DisableWritebackCacheRequest> _decoded_request(std::move(_request_buffer));
  auto _encode_request_result = ::fidl::Encode(std::move(_decoded_request));
  if (_encode_request_result.status != ZX_OK) {
    return ::fidl::DecodeResult<DisableWritebackCacheResponse>(_encode_request_result.status, _encode_request_result.error);
  }
  auto _call_result = ::fidl::Call<DisableWritebackCacheRequest, DisableWritebackCacheResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(_response_buffer));
  if (_call_result.status != ZX_OK) {
    return ::fidl::DecodeResult<DisableWritebackCacheResponse>(_call_result.status, _call_result.error);
  }
  auto _decode_result = ::fidl::Decode(std::move(_call_result.message));
  if (_decode_result.status != ZX_OK) {
    return _decode_result;
  }
  auto& _response = *_decode_result.message.message();
  *out_status = std::move(_response.status);
  return _decode_result;
}

::fidl::DecodeResult<Device::DisableWritebackCacheResponse> Device::InPlace::DisableWritebackCache(zx::unowned_channel _client_end, ::fidl::BytePart response_buffer) {
  constexpr uint32_t _write_num_bytes = sizeof(DisableWritebackCacheRequest);
  ::fidl::internal::AlignedBuffer<_write_num_bytes> _write_bytes;
  ::fidl::BytePart _request_buffer = _write_bytes.view();
  _request_buffer.set_actual(_write_num_bytes);
  ::fidl::DecodedMessage<DisableWritebackCacheRequest> params(std::move(_request_buffer));
  params.message()->_hdr = {};
  params.message()->_hdr.ordinal = kDevice_DisableWritebackCache_GenOrdinal;
  auto _encode_request_result = ::fidl::Encode(std::move(params));
  if (_encode_request_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Device::DisableWritebackCacheResponse>::FromFailure(
        std::move(_encode_request_result));
  }
  auto _call_result = ::fidl::Call<DisableWritebackCacheRequest, DisableWritebackCacheResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(response_buffer));
  if (_call_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Device::DisableWritebackCacheResponse>::FromFailure(
        std::move(_call_result));
  }
  return ::fidl::Decode(std::move(_call_result.message));
}

template <>
Device::ResultOf::SetWritebackCacheReported_Impl<Device::SetWritebackCacheReportedResponse>::SetWritebackCacheReported_Impl(zx::unowned_channel _client_end, bool report) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<SetWritebackCacheReportedRequest>();
  ::fidl::internal::AlignedBuffer<_kWriteAllocSize> _write_bytes_inlined;
  auto& _write_bytes_array = _write_bytes_inlined;
  uint8_t* _write_bytes = _write_bytes_array.view().data();
  memset(_write_bytes, 0, SetWritebackCacheReportedRequest::PrimarySize);
  auto& _request = *reinterpret_cast<SetWritebackCacheReportedRequest*>(_write_bytes);
  _request.report = std::move(report);
  ::fidl::BytePart _request_bytes(_write_bytes, _kWriteAllocSize, sizeof(SetWritebackCacheReportedRequest));
  ::fidl::DecodedMessage<SetWritebackCacheReportedRequest> _decoded_request(std::move(_request_bytes));
  Super::SetResult(
      Device::InPlace::SetWritebackCacheReported(std::move(_client_end), std::move(_decoded_request), Super::response_buffer()));
}

Device::ResultOf::SetWritebackCacheReported Device::SyncClient::SetWritebackCacheReported(bool report) {
  return ResultOf::SetWritebackCacheReported(zx::unowned_channel(this->channel_), std::move(report));
}

Device::ResultOf::SetWritebackCacheReported Device::Call::SetWritebackCacheReported(zx::unowned_channel _client_end, bool report) {
  return ResultOf::SetWritebackCacheReported(std::move(_client_end), std::move(report));
}

template <>
Device::UnownedResultOf::SetWritebackCacheReported_Impl<Device::SetWritebackCacheReportedResponse>::SetWritebackCacheReported_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, bool report, ::fidl::BytePart _response_buffer) {
  if (_request_buffer.capacity() < SetWritebackCacheReportedRequest::PrimarySize) {
    Super::SetFailure(::fidl::DecodeResult<SetWritebackCacheReportedResponse>(ZX_ERR_BUFFER_TOO_SMALL, ::fidl::internal::kErrorRequestBufferTooSmall));
    return;
  }
  memset(_request_buffer.data(), 0, SetWritebackCacheReportedRequest::PrimarySize);
  auto& _request = *reinterpret_cast<SetWritebackCacheReportedRequest*>(_request_buffer.data());
  _request.report = std::move(report);
  _request_buffer.set_actual(sizeof(SetWritebackCacheReportedRequest));
  ::fidl::DecodedMessage<SetWritebackCacheReportedRequest> _decoded_request(std::move(_request_buffer));
  Super::SetResult(
      Device::InPlace::SetWritebackCacheReported(std::move(_client_end), std::move(_decoded_request), std::move(_response_buffer)));
}

Device::UnownedResultOf::SetWritebackCacheReported Device::SyncClient::SetWritebackCacheReported(::fidl::BytePart _request_buffer, bool report, ::fidl::BytePart _response_buffer) {
  return UnownedResultOf::SetWritebackCacheReported(zx::unowned_channel(this->channel_), std::move(_request_buffer), std::move(report), std::move(_response_buffer));
}

Device::UnownedResultOf::SetWritebackCacheReported Device::Call::SetWritebackCacheReported(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, bool report, ::fidl::BytePart _response_buffer) {
  return UnownedResultOf::SetWritebackCacheReported(std::move(_client_end), std::move(_request_buffer), std::move(report), std::move(_response_buffer));
}

zx_status_t Device::SyncClient::SetWritebackCacheReported_Deprecated(bool report, int32_t* out_status) {
  return Device::Call::SetWritebackCacheReported_Deprecated(zx::unowned_channel(this->channel_), std::move(report), out_status);
}

zx_status_t Device::Call::SetWritebackCacheReported_Deprecated(zx::unowned_channel _client_end, bool report, int32_t* out_status) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<SetWritebackCacheReportedRequest>();
  FIDL_ALIGNDECL uint8_t _write_bytes[_kWriteAllocSize] = {};
  auto& _request = *reinterpret_cast<SetWritebackCacheReportedRequest*>(_write_bytes);
  _request._hdr.ordinal = kDevice_SetWritebackCacheReported_GenOrdinal;
  _request.report = std::move(report);
  ::fidl::BytePart _request_bytes(_write_bytes, _kWriteAllocSize, sizeof(SetWritebackCacheReportedRequest));
  ::fidl::DecodedMessage<SetWritebackCacheReportedRequest> _decoded_request(std::move(_request_bytes));
  auto _encode_request_result = ::fidl::Encode(std::move(_decoded_request));
  if (_encode_request_result.status != ZX_OK) {
    return _encode_request_result.status;
  }
  constexpr uint32_t _kReadAllocSize = ::fidl::internal::ClampedMessageSize<SetWritebackCacheReportedResponse>();
  FIDL_ALIGNDECL uint8_t _read_bytes[_kReadAllocSize];
  ::fidl::BytePart _response_bytes(_read_bytes, _kReadAllocSize);
  auto _call_result = ::fidl::Call<SetWritebackCacheReportedRequest, SetWritebackCacheReportedResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(_response_bytes));
  if (_call_result.status != ZX_OK) {
    return _call_result.status;
  }
  auto _decode_result = ::fidl::Decode(std::move(_call_result.message));
  if (_decode_result.status != ZX_OK) {
    return _decode_result.status;
  }
  auto& _response = *_decode_result.message.message();
  *out_status = std::move(_response.status);
  return ZX_OK;
}

::fidl::DecodeResult<Device::SetWritebackCacheReportedResponse> Device::SyncClient::SetWritebackCacheReported_Deprecated(::fidl::BytePart _request_buffer, bool report, ::fidl::BytePart _response_buffer, int32_t* out_status) {
  return Device::Call::SetWritebackCacheReported_Deprecated(zx::unowned_channel(this->channel_), std::move(_request_buffer), std::move(report), std::move(_response_buffer), out_status);
}

::fidl::DecodeResult<Device::SetWritebackCacheReportedResponse> Device::Call::SetWritebackCacheReported_Deprecated(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, bool report, ::fidl::BytePart _response_buffer, int32_t* out_status) {
  if (_request_buffer.capacity() < SetWritebackCacheReportedRequest::PrimarySize) {
    return ::fidl::DecodeResult<SetWritebackCacheReportedResponse>(ZX_ERR_BUFFER_TOO_SMALL, ::fidl::internal::kErrorRequestBufferTooSmall);
  }
  auto& _request = *reinterpret_cast<SetWritebackCacheReportedRequest*>(_request_buffer.data());
  _request._hdr.ordinal = kDevice_SetWritebackCacheReported_GenOrdinal;
  _request.report = std::move(report);
  _request_buffer.set_actual(sizeof(SetWritebackCacheReportedRequest));
  ::fidl::DecodedMessage<SetWritebackCacheReportedRequest> _decoded_request(std::move(_request_buffer));
  auto _encode_request_result = ::fidl::Encode(std::move(_decoded_request));
  if (_encode_request_result.status != ZX_OK) {
    return ::fidl::DecodeResult<SetWritebackCacheReportedResponse>(_encode_request_result.status, _encode_request_result.error);
  }
  auto _call_result = ::fidl::Call<SetWritebackCacheReportedRequest, SetWritebackCacheReportedResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(_response_buffer));
  if (_call_result.status != ZX_OK) {
    return ::fidl::DecodeResult<SetWritebackCacheReportedResponse>(_call_result.status, _call_result.error);
  }
  auto _decode_result = ::fidl::Decode(std::move(_call_result.message));
  if (_decode_result.status != ZX_OK) {
    return _decode_result;
  }
  auto& _response = *_decode_result.message.message();
  *out_status = std::move(_response.status);
  return _decode_result;
}

::fidl::DecodeResult<Device::SetWritebackCacheReportedResponse> Device::InPlace::SetWritebackCacheReported(zx::unowned_channel _client_end, ::fidl::DecodedMessage<SetWritebackCacheReportedRequest> params, ::fidl::BytePart response_buffer) {
  params.message()->_hdr = {};
  params.message()->_hdr.ordinal = kDevice_SetWritebackCacheReported_GenOrdinal;
  auto _encode_request_result = ::fidl::Encode(std::move(params));
  if (_encode_request_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Device::SetWritebackCacheReportedResponse>::FromFailure(
        std::move(_encode_request_result));
  }
  auto _call_result = ::fidl::Call<SetWritebackCacheReportedRequest, SetWritebackCacheReportedResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(response_buffer));
  if (_call_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Device::SetWritebackCacheReportedResponse>::FromFailure(
        std::move(_call_result));
  }
  return ::fidl::Decode(std::move(_call_result.message));
}


bool Device::TryDispatch(Interface* impl, fidl_msg_t* msg, ::fidl::Transaction* txn) {
  if (msg->num_bytes < sizeof(fidl_message_header_t)) {
    zx_handle_close_many(msg->handles, msg->num_handles);
    txn->Close(ZX_ERR_INVALID_ARGS);
    return true;
  }
  fidl_message_header_t* hdr = reinterpret_cast<fidl_message_header_t*>(msg->bytes);
  switch (hdr->ordinal) {
    case kDevice_EnableWritebackCache_GenOrdinal:
    {
      auto result = ::fidl::DecodeAs<EnableWritebackCacheRequest>(msg);
      if (result.status != ZX_OK) {
        txn->Close(ZX_ERR_INVALID_ARGS);
        return true;
      }
      impl->EnableWritebackCache(
        Interface::EnableWritebackCacheCompleter::Sync(txn));
      return true;
    }
    case kDevice_DisableWritebackCache_GenOrdinal:
    {
      auto result = ::fidl::DecodeAs<DisableWritebackCacheRequest>(msg);
      if (result.status != ZX_OK) {
        txn->Close(ZX_ERR_INVALID_ARGS);
        return true;
      }
      impl->DisableWritebackCache(
        Interface::DisableWritebackCacheCompleter::Sync(txn));
      return true;
    }
    case kDevice_SetWritebackCacheReported_GenOrdinal:
    {
      auto result = ::fidl::DecodeAs<SetWritebackCacheReportedRequest>(msg);
      if (result.status != ZX_OK) {
        txn->Close(ZX_ERR_INVALID_ARGS);
        return true;
      }
      auto message = result.message.message();
      impl->SetWritebackCacheReported(std::move(message->report),
        Interface::SetWritebackCacheReportedCompleter::Sync(txn));
      return true;
    }
    default: {
      return false;
    }
  }
}

bool Device::Dispatch(Interface* impl, fidl_msg_t* msg, ::fidl::Transaction* txn) {
  bool found = TryDispatch(impl, msg, txn);
  if (!found) {
    zx_handle_close_many(msg->handles, msg->num_handles);
    txn->Close(ZX_ERR_NOT_SUPPORTED);
  }
  return found;
}


void Device::Interface::EnableWritebackCacheCompleterBase::Reply(int32_t status) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<EnableWritebackCacheResponse>();
  FIDL_ALIGNDECL uint8_t _write_bytes[_kWriteAllocSize] = {};
  auto& _response = *reinterpret_cast<EnableWritebackCacheResponse*>(_write_bytes);
  _response._hdr.ordinal = kDevice_EnableWritebackCache_GenOrdinal;
  _response.status = std::move(status);
  ::fidl::BytePart _response_bytes(_write_bytes, _kWriteAllocSize, sizeof(EnableWritebackCacheResponse));
  CompleterBase::SendReply(::fidl::DecodedMessage<EnableWritebackCacheResponse>(std::move(_response_bytes)));
}

void Device::Interface::EnableWritebackCacheCompleterBase::Reply(::fidl::BytePart _buffer, int32_t status) {
  if (_buffer.capacity() < EnableWritebackCacheResponse::PrimarySize) {
    CompleterBase::Close(ZX_ERR_INTERNAL);
    return;
  }
  auto& _response = *reinterpret_cast<EnableWritebackCacheResponse*>(_buffer.data());
  _response._hdr.ordinal = kDevice_EnableWritebackCache_GenOrdinal;
  _response.status = std::move(status);
  _buffer.set_actual(sizeof(EnableWritebackCacheResponse));
  CompleterBase::SendReply(::fidl::DecodedMessage<EnableWritebackCacheResponse>(std::move(_buffer)));
}

void Device::Interface::EnableWritebackCacheCompleterBase::Reply(::fidl::DecodedMessage<EnableWritebackCacheResponse> params) {
  params.message()->_hdr = {};
  params.message()->_hdr.ordinal = kDevice_EnableWritebackCache_GenOrdinal;
  CompleterBase::SendReply(std::move(params));
}


void Device::Interface::DisableWritebackCacheCompleterBase::Reply(int32_t status) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<DisableWritebackCacheResponse>();
  FIDL_ALIGNDECL uint8_t _write_bytes[_kWriteAllocSize] = {};
  auto& _response = *reinterpret_cast<DisableWritebackCacheResponse*>(_write_bytes);
  _response._hdr.ordinal = kDevice_DisableWritebackCache_GenOrdinal;
  _response.status = std::move(status);
  ::fidl::BytePart _response_bytes(_write_bytes, _kWriteAllocSize, sizeof(DisableWritebackCacheResponse));
  CompleterBase::SendReply(::fidl::DecodedMessage<DisableWritebackCacheResponse>(std::move(_response_bytes)));
}

void Device::Interface::DisableWritebackCacheCompleterBase::Reply(::fidl::BytePart _buffer, int32_t status) {
  if (_buffer.capacity() < DisableWritebackCacheResponse::PrimarySize) {
    CompleterBase::Close(ZX_ERR_INTERNAL);
    return;
  }
  auto& _response = *reinterpret_cast<DisableWritebackCacheResponse*>(_buffer.data());
  _response._hdr.ordinal = kDevice_DisableWritebackCache_GenOrdinal;
  _response.status = std::move(status);
  _buffer.set_actual(sizeof(DisableWritebackCacheResponse));
  CompleterBase::SendReply(::fidl::DecodedMessage<DisableWritebackCacheResponse>(std::move(_buffer)));
}

void Device::Interface::DisableWritebackCacheCompleterBase::Reply(::fidl::DecodedMessage<DisableWritebackCacheResponse> params) {
  params.message()->_hdr = {};
  params.message()->_hdr.ordinal = kDevice_DisableWritebackCache_GenOrdinal;
  CompleterBase::SendReply(std::move(params));
}


void Device::Interface::SetWritebackCacheReportedCompleterBase::Reply(int32_t status) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<SetWritebackCacheReportedResponse>();
  FIDL_ALIGNDECL uint8_t _write_bytes[_kWriteAllocSize] = {};
  auto& _response = *reinterpret_cast<SetWritebackCacheReportedResponse*>(_write_bytes);
  _response._hdr.ordinal = kDevice_SetWritebackCacheReported_GenOrdinal;
  _response.status = std::move(status);
  ::fidl::BytePart _response_bytes(_write_bytes, _kWriteAllocSize, sizeof(SetWritebackCacheReportedResponse));
  CompleterBase::SendReply(::fidl::DecodedMessage<SetWritebackCacheReportedResponse>(std::move(_response_bytes)));
}

void Device::Interface::SetWritebackCacheReportedCompleterBase::Reply(::fidl::BytePart _buffer, int32_t status) {
  if (_buffer.capacity() < SetWritebackCacheReportedResponse::PrimarySize) {
    CompleterBase::Close(ZX_ERR_INTERNAL);
    return;
  }
  auto& _response = *reinterpret_cast<SetWritebackCacheReportedResponse*>(_buffer.data());
  _response._hdr.ordinal = kDevice_SetWritebackCacheReported_GenOrdinal;
  _response.status = std::move(status);
  _buffer.set_actual(sizeof(SetWritebackCacheReportedResponse));
  CompleterBase::SendReply(::fidl::DecodedMessage<SetWritebackCacheReportedResponse>(std::move(_buffer)));
}

void Device::Interface::SetWritebackCacheReportedCompleterBase::Reply(::fidl::DecodedMessage<SetWritebackCacheReportedResponse> params) {
  params.message()->_hdr = {};
  params.message()->_hdr.ordinal = kDevice_SetWritebackCacheReported_GenOrdinal;
  CompleterBase::SendReply(std::move(params));
}


}  // namespace block
}  // namespace peripheral
}  // namespace usb
}  // namespace hardware
}  // namespace fuchsia
}  // namespace llcpp
