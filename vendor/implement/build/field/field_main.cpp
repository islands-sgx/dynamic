#include "atfield/boundary_assembly_transform.h"
#include "atfield/boundary_transform.h"
#include "atfield/analyze/annotation_adapter.h"

#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using atfield::boundary::BoundaryAssemblyField;
using atfield::boundary::BoundaryFieldFragment;
using atfield::boundary::BoundaryTransformOptions;
using atfield::boundary::transform_boundary_assembly;
using atfield::boundary::transform_module;
using llvm::StringRef;

struct ManifestField {
  std::uint64_t id{0};
  std::uint64_t payload_ordinal{0};
  std::uint64_t function_ordinal{0};
  std::string name;
  std::string function;
  std::string linkage_name;
  std::string demangled_name;
  std::string marker_symbol;
  std::string continuation_symbol;
  std::string body_symbol;
  std::string pretouch_symbol;
  std::string field_enter_symbol;
  std::string normal_close_symbol;
  std::string field_exit_symbol;
  std::optional<std::uint64_t> stack_bytes;
};

struct Arguments {
  std::string command;
  std::map<std::string, std::string> values;
  std::vector<std::string> inputs;
};

std::string usage() {
  return
      "usage:\n"
      "  atfield-field ir --payload-ordinal N --input optimized.bc "
      "--output boundary.bc --manifest fields.json\n"
      "  atfield-field asm --manifest fields.json --input llc.s "
      "--output boundary.o\n"
      "  atfield-field merge --manifest obj1.field.json "
      "--manifest obj2.field.json --out fields.json\n";
}

std::optional<Arguments> parse_arguments(int argc, char **argv,
                                         std::string &error) {
  if (argc < 2) {
    error = "missing command";
    return std::nullopt;
  }
  Arguments result;
  result.command = argv[1];
  for (int index = 2; index < argc; ++index) {
    const std::string key = argv[index];
    if (key.size() < 3 || key[0] != '-' || key[1] != '-') {
      error = "unexpected positional argument: " + key;
      return std::nullopt;
    }
    if (index + 1 == argc) {
      error = "missing value for " + key;
      return std::nullopt;
    }
    const std::string value = argv[++index];
    if ((key == "--input" || key == "--manifest") &&
        result.command == "merge") {
      result.inputs.push_back(value);
    } else if (!result.values.emplace(key, value).second) {
      error = "duplicate option: " + key;
      return std::nullopt;
    }
  }
  return result;
}

std::optional<std::string> required(const Arguments &arguments,
                                    StringRef key, std::string &error) {
  const auto found = arguments.values.find(key.str());
  if (found == arguments.values.end() || found->second.empty()) {
    error = "missing required option " + key.str();
    return std::nullopt;
  }
  return found->second;
}

bool parse_unsigned_decimal(StringRef text, std::uint64_t &value) {
  if (text.empty() || (text.size() > 1 && text.front() == '0')) {
    return false;
  }
  const char *begin = text.data();
  const char *end = begin + text.size();
  const auto result = std::from_chars(begin, end, value, 10);
  return result.ec == std::errc{} && result.ptr == end;
}

bool parse_payload_ordinal(StringRef text, std::uint64_t &value) {
  if (text.starts_with("0x")) {
    text = text.drop_front(2);
    if (text.empty() || text.size() > 16) {
      return false;
    }
    const char *begin = text.data();
    const char *end = begin + text.size();
    const auto result = std::from_chars(begin, end, value, 16);
    return result.ec == std::errc{} && result.ptr == end;
  }
  return parse_unsigned_decimal(text, value);
}

std::string hex_u64(std::uint64_t value) {
  std::ostringstream output;
  output << "0x" << std::hex << std::nouppercase << std::setw(16)
         << std::setfill('0') << value;
  return output.str();
}

std::optional<std::uint64_t> parse_hex_u64(const llvm::json::Value *value) {
  if (value == nullptr) {
    return std::nullopt;
  }
  const auto text = value->getAsString();
  if (!text || text->size() != 18 || !text->starts_with("0x")) {
    return std::nullopt;
  }
  for (const char character : text->drop_front(2)) {
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f'))) {
      return std::nullopt;
    }
  }
  std::uint64_t result_value = 0;
  const char *begin = text->data() + 2;
  const char *end = text->data() + text->size();
  const auto result = std::from_chars(begin, end, result_value, 16);
  if (result.ec != std::errc{} || result.ptr != end) {
    return std::nullopt;
  }
  return result_value;
}

std::optional<std::string> json_string(const llvm::json::Object &object,
                                       StringRef key) {
  const auto value = object.getString(key);
  if (!value) {
    return std::nullopt;
  }
  return value->str();
}

bool read_manifest(const std::string &path, std::vector<ManifestField> &fields,
                   std::string &error) {
  auto buffer = llvm::MemoryBuffer::getFile(path);
  if (!buffer) {
    error = "cannot read manifest " + path + ": " + buffer.getError().message();
    return false;
  }
  auto parsed = llvm::json::parse((*buffer)->getBuffer());
  if (!parsed) {
    error = "invalid JSON in " + path + ": " + llvm::toString(parsed.takeError());
    return false;
  }
  const llvm::json::Object *object = parsed->getAsObject();
  if (object == nullptr) {
    error = "manifest root must be an object: " + path;
    return false;
  }
  const auto schema = object->getString("schema");
  if (!schema || *schema != "atfield-fields-v1") {
    error = "unsupported manifest schema in " + path;
    return false;
  }
  const llvm::json::Array *array = object->getArray("fields");
  if (array == nullptr) {
    error = "manifest fields must be an array: " + path;
    return false;
  }
  for (const llvm::json::Value &entry : *array) {
    const llvm::json::Object *field = entry.getAsObject();
    if (field == nullptr) {
      error = "manifest field must be an object: " + path;
      return false;
    }
    ManifestField item;
    const auto id = parse_hex_u64(field->get("id"));
    const llvm::json::Array *order = field->getArray("order");
    if (!id || order == nullptr || order->size() != 2) {
      error = "manifest field needs a hex uint64 id and two-part order: " + path;
      return false;
    }
    const auto payload = parse_hex_u64(&(*order)[0]);
    const auto function_ordinal_text = (*order)[1].getAsString();
    if (!payload || !function_ordinal_text ||
        !parse_unsigned_decimal(*function_ordinal_text, item.function_ordinal)) {
      error = "manifest field has invalid order: " + path;
      return false;
    }
    const auto name = json_string(*field, "name");
    const auto function = json_string(*field, "function");
    const auto linkage_name = json_string(*field, "linkage_name");
    const auto demangled_name = json_string(*field, "demangled_name");
    const auto marker = json_string(*field, "marker_symbol");
    const auto continuation = json_string(*field, "continuation_symbol");
    const auto body = json_string(*field, "body_symbol");
    const auto pretouch = json_string(*field, "pretouch_symbol");
    const auto enter = json_string(*field, "field_enter_symbol");
    const auto close = json_string(*field, "normal_close_symbol");
    const auto exit = json_string(*field, "field_exit_symbol");
    if (!name || !function || !linkage_name || !demangled_name ||
        !marker || !continuation || !body || !pretouch || !enter || !close || !exit) {
      error = "manifest field lacks a required symbol or function: " + path;
      return false;
    }
    item.id = *id;
    item.payload_ordinal = *payload;
    item.name = *name;
    item.function = *function;
    item.linkage_name = *linkage_name;
    item.demangled_name = *demangled_name;
    if (item.name != item.demangled_name || item.function != item.linkage_name) {
      error = "manifest name/linkage fields are inconsistent: " + path;
      return false;
    }
    item.marker_symbol = *marker;
    item.continuation_symbol = *continuation;
    item.body_symbol = *body;
    item.pretouch_symbol = *pretouch;
    item.field_enter_symbol = *enter;
    item.normal_close_symbol = *close;
    item.field_exit_symbol = *exit;
    if (const llvm::json::Value *stack = field->get("stack_bytes")) {
      if (!stack->getAsNull()) {
        const auto number = stack->getAsInteger();
        if (!number || *number <= 0) {
          error = "stack_bytes must be null or a positive integer: " + path;
          return false;
        }
        item.stack_bytes = static_cast<std::uint64_t>(*number);
      }
    }
    const std::string suffix = std::to_string(item.id);
    if (item.marker_symbol != "__atfield_marker_" + suffix ||
        item.continuation_symbol != "__atfield_after_marker_" + suffix ||
        item.body_symbol != "__atfield_body_" + suffix ||
        item.pretouch_symbol != "__atfield_pretouch_" + suffix ||
        item.field_enter_symbol != "__atfield_field_enter_" + suffix ||
        item.normal_close_symbol != "__atfield_normal_close_" + suffix ||
        item.field_exit_symbol != "__atfield_field_exit_" + suffix) {
      error = "manifest contains noncanonical boundary symbols: " + path;
      return false;
    }
    fields.push_back(std::move(item));
  }
  return true;
}

std::string quote_json(StringRef text) {
  constexpr char hex[] = "0123456789abcdef";
  std::string output;
  output.reserve(text.size() + 2);
  output.push_back('"');
  for (const char raw : text) {
    const auto value = static_cast<unsigned char>(raw);
    switch (value) {
    case '"': output += "\\\""; break;
    case '\\': output += "\\\\"; break;
    case '\b': output += "\\b"; break;
    case '\f': output += "\\f"; break;
    case '\n': output += "\\n"; break;
    case '\r': output += "\\r"; break;
    case '\t': output += "\\t"; break;
    default:
      if (value < 0x20) {
        output += "\\u00";
        output.push_back(hex[value >> 4]);
        output.push_back(hex[value & 0x0f]);
      } else {
        output.push_back(static_cast<char>(value));
      }
    }
  }
  output.push_back('"');
  return output;
}

std::string write_manifest(const std::vector<ManifestField> &fields) {
  std::ostringstream output;
  output << "{\n  \"schema\": \"atfield-fields-v1\",\n  \"fields\": [";
  if (!fields.empty()) {
    output << '\n';
  }
  for (std::size_t index = 0; index != fields.size(); ++index) {
    const ManifestField &field = fields[index];
    const std::string id = std::to_string(field.id);
    output << "    {\n"
           << "      \"id\": " << quote_json(hex_u64(field.id)) << ",\n"
           << "      \"name\": " << quote_json(field.name) << ",\n"
           << "      \"function\": " << quote_json(field.function) << ",\n"
           << "      \"linkage_name\": " << quote_json(field.linkage_name) << ",\n"
           << "      \"demangled_name\": " << quote_json(field.demangled_name) << ",\n"
           << "      \"order\": ["
           << quote_json(hex_u64(field.payload_ordinal)) << ", "
           << quote_json(std::to_string(field.function_ordinal)) << "],\n"
           << "      \"marker_symbol\": "
           << quote_json("__atfield_marker_" + id) << ",\n"
           << "      \"continuation_symbol\": "
           << quote_json("__atfield_after_marker_" + id) << ",\n"
           << "      \"body_symbol\": "
           << quote_json("__atfield_body_" + id) << ",\n"
           << "      \"pretouch_symbol\": "
           << quote_json("__atfield_pretouch_" + id) << ",\n"
           << "      \"field_enter_symbol\": "
           << quote_json("__atfield_field_enter_" + id) << ",\n"
           << "      \"normal_close_symbol\": "
           << quote_json("__atfield_normal_close_" + id) << ",\n"
           << "      \"field_exit_symbol\": "
           << quote_json("__atfield_field_exit_" + id) << ",\n"
           << "      \"stack_bytes\": ";
    if (field.stack_bytes) {
      output << *field.stack_bytes;
    } else {
      output << "null";
    }
    output << "\n    }";
    if (index + 1 != fields.size()) {
      output << ',';
    }
    output << '\n';
  }
  output << "  ],\n  \"selectors\": []\n}\n";
  return output.str();
}

bool write_text(const std::string &path, StringRef contents,
                std::string &error) {
  const std::filesystem::path output_path(path);
  if (output_path.has_parent_path()) {
    std::error_code filesystem_error;
    std::filesystem::create_directories(output_path.parent_path(),
                                        filesystem_error);
    if (filesystem_error) {
      error = "cannot create output directory: " + filesystem_error.message();
      return false;
    }
  }
  std::error_code stream_error;
  llvm::raw_fd_ostream output(path, stream_error, llvm::sys::fs::OF_Text);
  if (stream_error) {
    error = "cannot write " + path + ": " + stream_error.message();
    return false;
  }
  output << contents;
  output.flush();
  if (output.has_error()) {
    error = "write failed for " + path;
    return false;
  }
  return true;
}

bool command_ir(const Arguments &arguments, std::string &error) {
  const auto payload_text = required(arguments, "--payload-ordinal", error);
  const auto input_path = required(arguments, "--input", error);
  const auto output_path = required(arguments, "--output", error);
  const auto manifest_path = required(arguments, "--manifest", error);
  if (!payload_text || !input_path || !output_path || !manifest_path) {
    return false;
  }
  std::uint64_t payload_ordinal = 0;
  if (!parse_payload_ordinal(*payload_text, payload_ordinal)) {
    error = "payload ordinal must be an unsigned decimal or 0x hexadecimal uint64";
    return false;
  }

  llvm::LLVMContext context;
  llvm::SMDiagnostic diagnostic;
  std::unique_ptr<llvm::Module> module =
      llvm::parseIRFile(*input_path, diagnostic, context);
  if (!module) {
    std::string diagnostic_text;
    llvm::raw_string_ostream diagnostic_stream(diagnostic_text);
    diagnostic.print("atfield-field", diagnostic_stream);
    error = "cannot parse input IR: " + diagnostic_stream.str();
    return false;
  }
  auto fragment_or_error = transform_module(
      *module, BoundaryTransformOptions{.payload_ordinal = payload_ordinal});
  if (!fragment_or_error) {
    error = "Field IR transform failed: " + llvm::toString(fragment_or_error.takeError());
    return false;
  }

  std::vector<ManifestField> fields;
  fields.reserve(fragment_or_error->fields.size());
  for (const BoundaryFieldFragment &field : fragment_or_error->fields) {
    fields.push_back({.id = field.field_id,
                      .payload_ordinal = field.field_order_key.payload_ordinal,
                      .function_ordinal = field.field_order_key.function_ordinal,
                      .name = llvm::demangle(field.function_name),
                      .function = field.function_name,
                      .linkage_name = field.function_name,
                      .demangled_name = llvm::demangle(field.function_name),
                      .marker_symbol = "__atfield_marker_" + std::to_string(field.field_id),
                      .continuation_symbol = field.after_marker,
                      .body_symbol = field.body,
                      .pretouch_symbol = "__atfield_pretouch_" + std::to_string(field.field_id),
                      .field_enter_symbol = "__atfield_field_enter_" + std::to_string(field.field_id),
                      .normal_close_symbol = field.normal_close,
                      .field_exit_symbol = field.field_exit,
                      .stack_bytes = field.stack_bytes == 0
                                         ? std::optional<std::uint64_t>{}
                                         : std::optional<std::uint64_t>{field.stack_bytes}});
  }
  std::sort(fields.begin(), fields.end(), [](const ManifestField &left,
                                              const ManifestField &right) {
    return std::pair{left.payload_ordinal, left.function_ordinal} <
           std::pair{right.payload_ordinal, right.function_ordinal};
  });

  std::error_code output_error;
  llvm::raw_fd_ostream output(*output_path, output_error, llvm::sys::fs::OF_None);
  if (output_error) {
    error = "cannot write transformed IR " + *output_path + ": " + output_error.message();
    return false;
  }
  if (StringRef(*output_path).ends_with(".ll")) {
    module->print(output, nullptr);
  } else {
    llvm::WriteBitcodeToFile(*module, output);
  }
  output.flush();
  if (output.has_error()) {
    error = "writing transformed IR failed: " + *output_path;
    return false;
  }
  const std::string manifest = write_manifest(fields);
  if (!write_text(*manifest_path, manifest, error)) {
    return false;
  }
  return true;
}

bool command_asm(const Arguments &arguments, std::string &error) {
  const auto manifest_path = required(arguments, "--manifest", error);
  const auto input_path = required(arguments, "--input", error);
  const auto output_path = required(arguments, "--output", error);
  if (!manifest_path || !input_path || !output_path) {
    return false;
  }
  std::vector<ManifestField> fields;
  if (!read_manifest(*manifest_path, fields, error)) {
    return false;
  }
  auto assembly = llvm::MemoryBuffer::getFile(*input_path);
  if (!assembly) {
    error = "cannot read assembly " + *input_path + ": " + assembly.getError().message();
    return false;
  }
  std::vector<BoundaryAssemblyField> boundary_fields;
  boundary_fields.reserve(fields.size());
  for (const ManifestField &field : fields) {
    boundary_fields.push_back({.field_id = field.id,
                               .after_marker = field.continuation_symbol,
                               .body = field.body_symbol});
  }
  auto object_or_error = transform_boundary_assembly(
      (*assembly)->getBuffer(), boundary_fields);
  if (!object_or_error) {
    error = "Field assembly transform failed: " + llvm::toString(object_or_error.takeError());
    return false;
  }
  const std::filesystem::path object_path(*output_path);
  if (object_path.has_parent_path()) {
    std::error_code filesystem_error;
    std::filesystem::create_directories(object_path.parent_path(), filesystem_error);
    if (filesystem_error) {
      error = "cannot create output directory: " + filesystem_error.message();
      return false;
    }
  }
  std::error_code output_error;
  llvm::raw_fd_ostream output(*output_path, output_error, llvm::sys::fs::OF_None);
  if (output_error) {
    error = "cannot write transformed object " + *output_path + ": " + output_error.message();
    return false;
  }
  output.write(reinterpret_cast<const char *>(object_or_error->data()),
               static_cast<std::streamsize>(object_or_error->size()));
  output.flush();
  if (output.has_error()) {
    error = "writing transformed object failed: " + *output_path;
    return false;
  }
  return true;
}

bool command_merge(const Arguments &arguments, std::string &error) {
  auto output_path = required(arguments, "--out", error);
  if (!output_path) {
    error.clear();
    output_path = required(arguments, "--output", error);
  }
  if (!output_path) {
    return false;
  }
  if (arguments.inputs.empty()) {
    error = "merge requires at least one --input manifest";
    return false;
  }
  std::vector<ManifestField> fields;
  for (const std::string &path : arguments.inputs) {
    if (!read_manifest(path, fields, error)) {
      return false;
    }
  }
  std::sort(fields.begin(), fields.end(), [](const ManifestField &left,
                                              const ManifestField &right) {
    return std::pair{left.payload_ordinal, left.function_ordinal} <
           std::pair{right.payload_ordinal, right.function_ordinal};
  });
  std::set<std::uint64_t> ids;
  std::set<std::pair<std::uint64_t, std::uint64_t>> order_keys;
  for (const ManifestField &field : fields) {
    if (!ids.insert(field.id).second) {
      error = "Field ID collision across payload manifests: " + hex_u64(field.id);
      return false;
    }
    if (!order_keys.emplace(field.payload_ordinal, field.function_ordinal).second) {
      error = "duplicate Field order key in payload manifests";
      return false;
    }
  }
  return write_text(*output_path, write_manifest(fields), error);
}

} // namespace

int main(int argc, char **argv) {
  std::string error;
  if (argc == 2 && (StringRef(argv[1]) == "--help" ||
                    StringRef(argv[1]) == "-h")) {
    llvm::outs() << usage();
    return 0;
  }
  const auto arguments = parse_arguments(argc, argv, error);
  if (!arguments) {
    llvm::errs() << error << '\n' << usage();
    return 64;
  }
  bool success = false;
  if (arguments->command == "ir") {
    success = command_ir(*arguments, error);
  } else if (arguments->command == "asm") {
    success = command_asm(*arguments, error);
  } else if (arguments->command == "merge") {
    success = command_merge(*arguments, error);
  } else {
    error = "unknown command: " + arguments->command;
  }
  if (!success) {
    llvm::errs() << error << '\n';
    return 1;
  }
  return 0;
}
