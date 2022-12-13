#include "quiche/binary_http/binary_http_message.h"

#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "gquiche/common/quiche_data_reader.h"
#include "gquiche/common/quiche_data_writer.h"

namespace quiche {
namespace {

constexpr uint8_t kKnownLengthRequestFraming = 0;
constexpr uint8_t kKnownLengthResponseFraming = 1;

bool ReadStringValue(quiche::QuicheDataReader& reader, std::string& data) {
  absl::string_view data_view;
  if (!reader.ReadStringPieceVarInt62(&data_view)) {
    return false;
  }
  data = std::string(data_view);
  return true;
}

absl::StatusOr<BinaryHttpRequest::ControlData> DecodeControlData(
    quiche::QuicheDataReader& reader) {
  BinaryHttpRequest::ControlData control_data;
  if (!ReadStringValue(reader, control_data.method)) {
    return absl::InvalidArgumentError("Failed to read method.");
  }
  if (!ReadStringValue(reader, control_data.scheme)) {
    return absl::InvalidArgumentError("Failed to read scheme.");
  }
  if (!ReadStringValue(reader, control_data.authority)) {
    return absl::InvalidArgumentError("Failed to read authority.");
  }
  if (!ReadStringValue(reader, control_data.path)) {
    return absl::InvalidArgumentError("Failed to read path.");
  }
  return control_data;
}

absl::Status DecodeFields(
    quiche::QuicheDataReader& reader,
    const std::function<void(absl::string_view name, absl::string_view value)>&
        callback) {
  absl::string_view fields;
  if (!reader.ReadStringPieceVarInt62(&fields)) {
    return absl::InvalidArgumentError("Failed to read fields.");
  }
  quiche::QuicheDataReader fields_reader(fields);
  while (!fields_reader.IsDoneReading()) {
    absl::string_view name;
    if (!fields_reader.ReadStringPieceVarInt62(&name)) {
      return absl::InvalidArgumentError("Failed to read field name.");
    }
    absl::string_view value;
    if (!fields_reader.ReadStringPieceVarInt62(&value)) {
      return absl::InvalidArgumentError("Failed to read field value.");
    }
    callback(name, value);
  }
  return absl::OkStatus();
}

absl::Status DecodeFieldsAndBody(quiche::QuicheDataReader& reader,
                                 BinaryHttpMessage& message) {
  if (const absl::Status status = DecodeFields(
          reader,
          [&message](absl::string_view name, absl::string_view value) {
            message.AddHeaderField({std::string(name), std::string(value)});
          });
      !status.ok()) {
    return status;
  }
  // TODO(bschneider): Handle case where remaining message is truncated.
  // Skip it on encode as well.
  // https://www.ietf.org/archive/id/draft-ietf-httpbis-binary-message-06.html#name-padding-and-truncation
  absl::string_view body;
  if (!reader.ReadStringPieceVarInt62(&body)) {
    return absl::InvalidArgumentError("Failed to read body.");
  }
  message.set_body(std::string(body));
  // TODO(bschneider): Check for / read-in any trailer-fields
  return absl::OkStatus();
}

absl::StatusOr<BinaryHttpRequest> DecodeKnownLengthRequest(
    quiche::QuicheDataReader& reader) {
  const auto control_data = DecodeControlData(reader);
  if (!control_data.ok()) {
    return control_data.status();
  }
  BinaryHttpRequest request(std::move(*control_data));
  if (const absl::Status status = DecodeFieldsAndBody(reader, request);
      !status.ok()) {
    return status;
  }
  return request;
}

absl::StatusOr<BinaryHttpResponse> DecodeKnownLengthResponse(
    quiche::QuicheDataReader& reader) {
  std::vector<std::pair<uint16_t, std::vector<BinaryHttpMessage::Field>>>
      informational_responses;
  uint64_t status_code;
  bool reading_response_control_data = true;
  while (reading_response_control_data) {
    if (!reader.ReadVarInt62(&status_code)) {
      return absl::InvalidArgumentError("Failed to read status code.");
    }
    if (status_code >= 100 && status_code <= 199) {
      std::vector<BinaryHttpMessage::Field> fields;
      if (const absl::Status status = DecodeFields(
              reader,
              [&fields](absl::string_view name, absl::string_view value) {
                fields.push_back({std::string(name), std::string(value)});
              });
          !status.ok()) {
        return status;
      }
      informational_responses.emplace_back(status_code, std::move(fields));
    } else {
      reading_response_control_data = false;
    }
  }
  BinaryHttpResponse response(status_code);
  for (const auto& informational_response : informational_responses) {
    if (const absl::Status status = response.AddInformationalResponse(
            informational_response.first,
            std::move(informational_response.second));
        !status.ok()) {
      return status;
    }
  }
  if (const absl::Status status = DecodeFieldsAndBody(reader, response);
      !status.ok()) {
    return status;
  }
  return response;
}

uint64_t StringPieceVarInt62Len(absl::string_view s) {
  return quiche::QuicheDataWriter::GetVarInt62Len(s.length()) + s.length();
}

}  // namespace

void BinaryHttpMessage::Fields::AddField(BinaryHttpMessage::Field field) {
  fields_.push_back(std::move(field));
}

// Encode fields in the order they were initially inserted.
// Updates do not change order.
absl::Status BinaryHttpMessage::Fields::Encode(
    quiche::QuicheDataWriter& writer) const {
  if (!writer.WriteVarInt62(EncodedFieldsSize())) {
    return absl::InvalidArgumentError("Failed to write encoded field size.");
  }
  for (const BinaryHttpMessage::Field& field : fields_) {
    if (!writer.WriteStringPieceVarInt62(field.name)) {
      return absl::InvalidArgumentError("Failed to write field name.");
    }
    if (!writer.WriteStringPieceVarInt62(field.value)) {
      return absl::InvalidArgumentError("Failed to write field value.");
    }
  }
  return absl::OkStatus();
}

uint64_t BinaryHttpMessage::Fields::EncodedSize() const {
  uint64_t size = EncodedFieldsSize();
  return size + quiche::QuicheDataWriter::GetVarInt62Len(size);
}

uint64_t BinaryHttpMessage::Fields::EncodedFieldsSize() const {
  uint64_t size = 0;
  for (const BinaryHttpMessage::Field& field : fields_) {
    size += StringPieceVarInt62Len(field.name) +
            StringPieceVarInt62Len(field.value);
  }
  return size;
}

BinaryHttpMessage* BinaryHttpMessage::AddHeaderField(
    BinaryHttpMessage::Field field) {
  const std::string lower_name = absl::AsciiStrToLower(field.name);
  if (lower_name == "host") {
    has_host_ = true;
  }
  header_fields_.AddField({std::move(lower_name), std::move(field.value)});
  return this;
}

// Appends the encoded fields and body to data.
absl::Status BinaryHttpMessage::EncodeKnownLengthFieldsAndBody(
    quiche::QuicheDataWriter& writer) const {
  if (const absl::Status status = header_fields_.Encode(writer); !status.ok()) {
    return status;
  }
  if (!writer.WriteStringPieceVarInt62(body_)) {
    return absl::InvalidArgumentError("Failed to encode body.");
  }
  // TODO(bschneider): Consider support for trailer fields on known-length
  // requests. Trailers are atypical for a known-length request.
  return absl::OkStatus();
}

uint64_t BinaryHttpMessage::EncodedKnownLengthFieldsAndBodySize() const {
  return header_fields_.EncodedSize() + StringPieceVarInt62Len(body_);
}

absl::Status BinaryHttpResponse::AddInformationalResponse(
    uint16_t status_code, std::vector<Field> header_fields) {
  if (status_code < 100) {
    return absl::InvalidArgumentError("status code < 100");
  }
  if (status_code > 199) {
    return absl::InvalidArgumentError("status code > 199");
  }
  InformationalResponseInternal data(status_code);
  for (Field& header : header_fields) {
    data.AddField(header.name, std::move(header.value));
  }
  informational_response_control_data_.push_back(std::move(data));
  return absl::OkStatus();
}

absl::StatusOr<std::string> BinaryHttpResponse::Serialize() const {
  // Only supporting known length requests so far.
  return EncodeAsKnownLength();
}

std::vector<BinaryHttpResponse::InformationalResponse>
BinaryHttpResponse::GetInformationalResponse() const {
  std::vector<InformationalResponse> data;
  data.reserve(informational_response_control_data_.size());
  for (const auto& control_data : informational_response_control_data_) {
    data.push_back({control_data.response_code(), control_data.fields()});
  }
  return data;
}

absl::StatusOr<std::string> BinaryHttpResponse::EncodeAsKnownLength() const {
  std::string data;
  data.resize(EncodedSize());
  quiche::QuicheDataWriter writer(data.size(), data.data());
  if (!writer.WriteUInt8(kKnownLengthResponseFraming)) {
    return absl::InvalidArgumentError("Failed to write framing indicator");
  }
  // Informational response
  for (const auto& informational : informational_response_control_data_) {
    if (const absl::Status status = informational.Encode(writer);
        !status.ok()) {
      return status;
    }
  }
  if (!writer.WriteVarInt62(status_code_)) {
    return absl::InvalidArgumentError("Failed to write status code");
  }
  if (const absl::Status status = EncodeKnownLengthFieldsAndBody(writer);
      !status.ok()) {
    return status;
  }
  QUICHE_DCHECK_EQ(writer.remaining(), 0u);
  return data;
}

uint64_t BinaryHttpResponse::EncodedSize() const {
  uint64_t size = sizeof(kKnownLengthResponseFraming);
  for (const auto& informational : informational_response_control_data_) {
    size += informational.EncodedSize();
  }
  return size + quiche::QuicheDataWriter::GetVarInt62Len(status_code_) +
         EncodedKnownLengthFieldsAndBodySize();
}

void BinaryHttpResponse::InformationalResponseInternal::AddField(
    absl::string_view name, std::string value) {
  fields_.AddField({absl::AsciiStrToLower(name), std::move(value)});
}

// Appends the encoded fields and body to data.
absl::Status BinaryHttpResponse::InformationalResponseInternal::Encode(
    quiche::QuicheDataWriter& writer) const {
  writer.WriteVarInt62(response_code_);
  return fields_.Encode(writer);
}

uint64_t BinaryHttpResponse::InformationalResponseInternal::EncodedSize()
    const {
  return quiche::QuicheDataWriter::GetVarInt62Len(response_code_) +
         fields_.EncodedSize();
}

absl::StatusOr<std::string> BinaryHttpRequest::Serialize() const {
  // Only supporting known length requests so far.
  return EncodeAsKnownLength();
}

// https://www.ietf.org/archive/id/draft-ietf-httpbis-binary-message-06.html#name-request-control-data
absl::Status BinaryHttpRequest::EncodeControlData(
    quiche::QuicheDataWriter& writer) const {
  if (!writer.WriteStringPieceVarInt62(control_data_.method)) {
    return absl::InvalidArgumentError("Failed to encode method.");
  }
  if (!writer.WriteStringPieceVarInt62(control_data_.scheme)) {
    return absl::InvalidArgumentError("Failed to encode scheme.");
  }
  // the Host header field is not replicated in the :authority field, as is
  // required for ensuring that the request is reproduced accurately; see
  // Section 8.1.2.3 of [H2].
  if (!has_host()) {
    if (!writer.WriteStringPieceVarInt62(control_data_.authority)) {
      return absl::InvalidArgumentError("Failed to encode authority.");
    }
  } else {
    if (!writer.WriteStringPieceVarInt62("")) {
      return absl::InvalidArgumentError("Failed to encode authority.");
    }
  }
  if (!writer.WriteStringPieceVarInt62(control_data_.path)) {
    return absl::InvalidArgumentError("Failed to encode path.");
  }
  return absl::OkStatus();
}

uint64_t BinaryHttpRequest::EncodedControlDataSize() const {
  uint64_t size = StringPieceVarInt62Len(control_data_.method) +
                  StringPieceVarInt62Len(control_data_.scheme) +
                  StringPieceVarInt62Len(control_data_.path);
  if (!has_host()) {
    size += StringPieceVarInt62Len(control_data_.authority);
  } else {
    size += StringPieceVarInt62Len("");
  }
  return size;
}

uint64_t BinaryHttpRequest::EncodedSize() const {
  return sizeof(kKnownLengthRequestFraming) + EncodedControlDataSize() +
         EncodedKnownLengthFieldsAndBodySize();
}

// https://www.ietf.org/archive/id/draft-ietf-httpbis-binary-message-06.html#name-known-length-messages
absl::StatusOr<std::string> BinaryHttpRequest::EncodeAsKnownLength() const {
  std::string data;
  data.resize(EncodedSize());
  quiche::QuicheDataWriter writer(data.size(), data.data());
  if (!writer.WriteUInt8(kKnownLengthRequestFraming)) {
    return absl::InvalidArgumentError("Failed to encode framing indicator.");
  }
  if (const absl::Status status = EncodeControlData(writer); !status.ok()) {
    return status;
  }
  if (const absl::Status status = EncodeKnownLengthFieldsAndBody(writer);
      !status.ok()) {
    return status;
  }
  QUICHE_DCHECK_EQ(writer.remaining(), 0u);
  return data;
}

absl::StatusOr<BinaryHttpRequest> BinaryHttpRequest::Create(
    absl::string_view data) {
  quiche::QuicheDataReader reader(data);
  uint8_t framing;
  if (!reader.ReadUInt8(&framing)) {
    return absl::InvalidArgumentError("Missing framing indicator.");
  }
  if (framing == kKnownLengthRequestFraming) {
    return DecodeKnownLengthRequest(reader);
  }
  return absl::UnimplementedError(
      absl::StrCat("Unsupported framing type ", framing));
}

absl::StatusOr<BinaryHttpResponse> BinaryHttpResponse::Create(
    absl::string_view data) {
  quiche::QuicheDataReader reader(data);
  uint8_t framing;
  if (!reader.ReadUInt8(&framing)) {
    return absl::InvalidArgumentError("Missing framing indicator.");
  }
  if (framing == kKnownLengthResponseFraming) {
    return DecodeKnownLengthResponse(reader);
  }
  return absl::UnimplementedError(
      absl::StrCat("Unsupported framing type ", framing));
}

}  // namespace quiche
