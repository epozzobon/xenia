/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/kernel/xam/content_manager.h"

#include <string>

#include "third_party/fmt/include/fmt/format.h"
#include "xenia/base/filesystem.h"
#include "xenia/base/string.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/xobject.h"
#include "xenia/vfs/devices/stfs_container_device.h"

namespace xe {
namespace kernel {
namespace xam {

static const char* kThumbnailFileName = "__thumbnail.png";

static const char* kGameUserContentDirName = "profile";

static int content_device_id_ = 0;

ContentPackage::ContentPackage(KernelState* kernel_state,
                               const std::string_view root_name,
                               const XCONTENT_DATA& data,
                               const std::filesystem::path& package_path,
                               bool create)
    : kernel_state_(kernel_state), root_name_(root_name) {
  device_path_ = fmt::format("\\Device\\Content\\{0}\\", ++content_device_id_);
  content_data_ = data;

  auto fs = kernel_state_->file_system();
  auto device = std::make_unique<vfs::StfsContainerDevice>(
      device_path_, package_path, create);
  device->Initialize();
  fs->RegisterDevice(std::move(device));
  fs->RegisterSymbolicLink(root_name_ + ":", device_path_);
}

ContentPackage::~ContentPackage() {
  auto fs = kernel_state_->file_system();
  fs->UnregisterSymbolicLink(root_name_ + ":");
  fs->UnregisterDevice(device_path_);
}

ContentManager::ContentManager(KernelState* kernel_state,
                               const std::filesystem::path& root_path)
    : kernel_state_(kernel_state), root_path_(root_path) {}

ContentManager::~ContentManager() = default;

std::filesystem::path ContentManager::ResolvePackageRoot(
    XContentType content_type) {
  auto title_id = fmt::format("{:08X}", kernel_state_->title_id());
  auto type_id = fmt::format("{:08X}", uint32_t(content_type));

  // Package root path:
  // content_root/title_id/type_id/
  return root_path_ / title_id / type_id;
}

std::filesystem::path ContentManager::ResolvePackagePath(
    const XCONTENT_DATA& data) {
  // Content path:
  // content_root/title_id/content_type/data_file_name
  auto package_root = ResolvePackageRoot(data.content_type);
  return package_root / xe::to_path(data.file_name());
}

std::vector<XCONTENT_DATA> ContentManager::ListContent(
    uint32_t device_id, XContentType content_type) {
  std::vector<XCONTENT_DATA> result;

  // Search path:
  // content_root/title_id/content_type/*
  auto package_root = ResolvePackageRoot(content_type);
  auto file_infos = xe::filesystem::ListFiles(package_root);
  for (const auto& file_info : file_infos) {
    if (file_info.type != xe::filesystem::FileInfo::Type::kFile) {
      // Files only.
      continue;
    }
    if (file_info.total_size < sizeof(vfs::StfsHeader)) {
      // Too small to be valid package
      continue;
    }

    auto file_path = file_info.path / file_info.name;

    // Check file magic before reading with StfsContainerDevice...
    auto file = xe::filesystem::OpenFile(file_path, "rb");
    vfs::XContentHeader header;
    auto read = fread(&header, sizeof(header), 1, file);
    fclose(file);

    if (!read || !header.is_magic_valid()) {
      // Invalid file magic
      continue;
    }

    auto device = std::make_unique<vfs::StfsContainerDevice>(
        fmt::format("\\Device\\Content\\{0}\\", ++content_device_id_),
        file_path);
    device->Initialize();

    XCONTENT_DATA content_data;
    content_data.device_id = device_id;
    content_data.content_type = device->header().metadata.content_type;
    content_data.set_display_name(
        device->header().metadata.display_name(XLanguage::kEnglish));
    content_data.set_file_name(path_to_utf8(file_info.name));

    result.emplace_back(std::move(content_data));
  }

  return result;
}

std::unique_ptr<ContentPackage> ContentManager::ResolvePackage(
    const std::string_view root_name, const XCONTENT_DATA& data, bool create) {
  auto package_path = ResolvePackagePath(data);
  if (!create && !std::filesystem::exists(package_path)) {
    return nullptr;
  }

  auto global_lock = global_critical_region_.Acquire();

  auto package = std::make_unique<ContentPackage>(kernel_state_, root_name,
                                                  data, package_path, create);
  return package;
}

bool ContentManager::ContentExists(const XCONTENT_DATA& data) {
  auto path = ResolvePackagePath(data);
  return std::filesystem::exists(path);
}

X_RESULT ContentManager::CreateContent(const std::string_view root_name,
                                       const XCONTENT_DATA& data) {
  auto global_lock = global_critical_region_.Acquire();

  if (open_packages_.count(string_key(root_name))) {
    // Already content open with this root name.
    return X_ERROR_ALREADY_EXISTS;
  }

  auto package_path = ResolvePackagePath(data);
  if (std::filesystem::exists(package_path)) {
    // Exists, must not!
    return X_ERROR_ALREADY_EXISTS;
  }

  auto parent = package_path.parent_path();
  std::filesystem::create_directories(parent);
  if (!std::filesystem::exists(parent)) {
    // Failed to create parent path?
    return X_ERROR_ACCESS_DENIED;
  }

  auto package = ResolvePackage(root_name, data, true);
  assert_not_null(package);

  open_packages_.insert({string_key::create(root_name), package.release()});

  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::OpenContent(const std::string_view root_name,
                                     const XCONTENT_DATA& data) {
  auto global_lock = global_critical_region_.Acquire();

  if (open_packages_.count(string_key(root_name))) {
    // Already content open with this root name.
    return X_ERROR_ALREADY_EXISTS;
  }

  auto package_path = ResolvePackagePath(data);
  if (!std::filesystem::exists(package_path)) {
    // Does not exist, must be created.
    return X_ERROR_FILE_NOT_FOUND;
  }

  // Open package.
  auto package = ResolvePackage(root_name, data);
  assert_not_null(package);

  open_packages_.insert({string_key::create(root_name), package.release()});

  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::CloseContent(const std::string_view root_name) {
  auto global_lock = global_critical_region_.Acquire();

  auto it = open_packages_.find(string_key(root_name));
  if (it == open_packages_.end()) {
    return X_ERROR_FILE_NOT_FOUND;
  }

  auto package = it->second;
  open_packages_.erase(it);
  delete package;

  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::GetContentThumbnail(const XCONTENT_DATA& data,
                                             std::vector<uint8_t>* buffer) {
  auto global_lock = global_critical_region_.Acquire();
  auto package_path = ResolvePackagePath(data);
  auto thumb_path = package_path / kThumbnailFileName;
  if (std::filesystem::exists(thumb_path)) {
    auto file = xe::filesystem::OpenFile(thumb_path, "rb");
    fseek(file, 0, SEEK_END);
    size_t file_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    buffer->resize(file_len);
    fread(const_cast<uint8_t*>(buffer->data()), 1, buffer->size(), file);
    fclose(file);
    return X_ERROR_SUCCESS;
  } else {
    return X_ERROR_FILE_NOT_FOUND;
  }
}

X_RESULT ContentManager::SetContentThumbnail(const XCONTENT_DATA& data,
                                             std::vector<uint8_t> buffer) {
  auto global_lock = global_critical_region_.Acquire();
  auto package_path = ResolvePackagePath(data);
  // std::filesystem::create_directories(package_path);
  /*if (std::filesystem::exists(package_path)) {
    auto thumb_path = package_path / kThumbnailFileName;
    auto file = xe::filesystem::OpenFile(thumb_path, "wb");
    fwrite(buffer.data(), 1, buffer.size(), file);
    fclose(file);
    return X_ERROR_SUCCESS;
  } else {
    return X_ERROR_FILE_NOT_FOUND;
  }*/
  return X_ERROR_SUCCESS;
}

X_RESULT ContentManager::DeleteContent(const XCONTENT_DATA& data) {
  auto global_lock = global_critical_region_.Acquire();

  if (IsContentOpen(data)) {
    // TODO(Gliniak): Get real error code for this case.
    return X_ERROR_ACCESS_DENIED;
  }

  auto package_path = ResolvePackagePath(data);
  if (std::filesystem::remove_all(package_path) > 0) {
    return X_ERROR_SUCCESS;
  } else {
    return X_ERROR_FILE_NOT_FOUND;
  }
}

std::filesystem::path ContentManager::ResolveGameUserContentPath() {
  auto title_id = fmt::format("{:8X}", kernel_state_->title_id());
  auto user_name = xe::to_path(kernel_state_->user_profile()->name());

  // Per-game per-profile data location:
  // content_root/title_id/profile/user_name
  return root_path_ / title_id / kGameUserContentDirName / user_name;
}

bool ContentManager::IsContentOpen(const XCONTENT_DATA& data) const {
  return std::any_of(open_packages_.cbegin(), open_packages_.cend(),
                     [data](std::pair<string_key, ContentPackage*> content) {
                       return data == content.second->GetPackageContentData();
                     });
}

}  // namespace xam
}  // namespace kernel
}  // namespace xe
