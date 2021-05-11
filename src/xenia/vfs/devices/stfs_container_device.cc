/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/vfs/devices/stfs_container_device.h"

#include <algorithm>
#include <queue>
#include <vector>

#include "third_party/crypto/TinySHA1.hpp"
#include "xenia/base/logging.h"
#include "xenia/base/math.h"
#include "xenia/vfs/devices/stfs_container_entry.h"

#if XE_PLATFORM_WIN32
#include "xenia/base/platform_win.h"
#define timegm _mkgmtime
#endif

namespace xe {
namespace vfs {

// Convert FAT timestamp to 100-nanosecond intervals since January 1, 1601 (UTC)
uint64_t decode_fat_timestamp(uint32_t date, uint32_t time) {
  struct tm tm = {0};
  // 80 is the difference between 1980 (FAT) and 1900 (tm);
  tm.tm_year = ((0xFE00 & date) >> 9) + 80;
  tm.tm_mon = (0x01E0 & date) >> 5;
  tm.tm_mday = (0x001F & date) >> 0;
  tm.tm_hour = (0xF800 & time) >> 11;
  tm.tm_min = (0x07E0 & time) >> 5;
  tm.tm_sec = (0x001F & time) << 1;  // the value stored in 2-seconds intervals
  tm.tm_isdst = 0;
  time_t timet = timegm(&tm);
  if (timet == -1) {
    return 0;
  }
  // 11644473600LL is a difference between 1970 and 1601
  return (timet + 11644473600LL) * 10000000;
}

// TODO: check if this works!
std::tuple<uint32_t, uint32_t> encode_fat_timestamp(uint64_t timestamp) {
  time_t time_ = (timestamp / 10000000) - 11644473600LL;
  // Workaround for unset timestamps
  if (!timestamp) {
    time_ = 0;
  }
  auto* tm = gmtime(&time_);

  uint32_t date = (tm->tm_year << 9) & 0xFE00;
  date |= (tm->tm_mon << 5) & 0x1E0;
  date |= (tm->tm_mday << 0) & 0x1F;

  uint32_t time = (tm->tm_hour << 11) & 0xF800;
  time |= (tm->tm_min << 5) & 0x7E0;
  time |= (tm->tm_sec >> 1) & 0x1F;

  return std::make_tuple(date, time);
}

StfsContainerDevice::StfsContainerDevice(const std::string_view mount_path,
                                         const std::filesystem::path& host_path,
                                         bool create)
    : Device(mount_path),
      name_("STFS"),
      host_path_(host_path),
      allow_creating_(create),
      files_total_size_(),
      svod_base_offset_(),
      header_(),
      svod_layout_(),
      blocks_per_hash_table_(1),
      block_step_{0, 0} {}

StfsContainerDevice::~StfsContainerDevice() { CloseFiles(); }

void StfsContainerDevice::Dump(StringBuffer* string_buffer) {
  auto global_lock = global_critical_region_.Acquire();
  root_entry_->Dump(string_buffer, 0);
}

Entry* StfsContainerDevice::ResolvePath(const std::string_view path) {
  // The filesystem will have stripped our prefix off already, so the path will
  // be in the form:
  // some\PATH.foo
  XELOGFS("StfsContainerDevice::ResolvePath({})", path);
  return root_entry_->ResolvePath(path);
}

XContentPackageType StfsContainerDevice::ReadMagic(
    const std::filesystem::path& path) {
  auto map = MappedMemory::Open(path, MappedMemory::Mode::kRead, 0, 4);
  return XContentPackageType(xe::load_and_swap<uint32_t>(map->data()));
}

bool StfsContainerDevice::ResolveFromFolder(const std::filesystem::path& path) {
  // Scan through folders until a file with magic is found
  std::queue<filesystem::FileInfo> queue;

  filesystem::FileInfo folder;
  filesystem::GetInfo(host_path_, &folder);
  queue.push(folder);

  while (!queue.empty()) {
    auto current_file = queue.front();
    queue.pop();

    if (current_file.type == filesystem::FileInfo::Type::kDirectory) {
      auto path = current_file.path / current_file.name;
      auto child_files = filesystem::ListFiles(path);
      for (auto file : child_files) {
        queue.push(file);
      }
    } else {
      // Try to read the file's magic
      auto path = current_file.path / current_file.name;
      auto magic = ReadMagic(path);

      if (magic == XContentPackageType::kCon ||
          magic == XContentPackageType::kLive ||
          magic == XContentPackageType::kPirs) {
        host_path_ = current_file.path / current_file.name;
        XELOGI("STFS Package found: {}", xe::path_to_utf8(host_path_));
        return true;
      }
    }
  }

  if (host_path_ == path) {
    // Could not find a suitable container file
    return false;
  }
  return true;
}

bool StfsContainerDevice::Initialize() {
  // Resolve a valid STFS file if a directory is given.
  if (std::filesystem::is_directory(host_path_) &&
      !ResolveFromFolder(host_path_)) {
    XELOGE("Could not resolve an STFS container given path {}",
           xe::path_to_utf8(host_path_));
    return false;
  }

  // Open the data file(s)
  auto open_result = OpenFiles();
  if (open_result != Error::kSuccess) {
    XELOGE("Failed to open STFS container: {}", open_result);
    return false;
  }

  switch (header_.metadata.volume_type) {
    case XContentVolumeType::kStfs:
      return STFSReadDirectory();
      break;
    case XContentVolumeType::kSvod:
      return ReadSVOD() == Error::kSuccess;
    default:
      XELOGE("Unknown XContent volume type: {}",
             xe::byte_swap(uint32_t(header_.metadata.volume_type.value)));
      return false;
  }
}

StfsContainerDevice::Error StfsContainerDevice::OpenFiles() {
  // Map the file containing the STFS Header and read it.
  XELOGI("Loading STFS header file: {}", xe::path_to_utf8(host_path_));

  // Open file for read/write if it exists, else if creating was requested we'll
  // create a new file
  FILE* header_file = nullptr;
  if (std::filesystem::exists(host_path_)) {
    header_file = xe::filesystem::OpenFile(host_path_, "rb+");
  } else {
    if (allow_creating_) {
      header_file = xe::filesystem::OpenFile(host_path_, "wb+");
    } else {
      XELOGE("Error opening STFS header file, file doesn't exist");
      return Error::kErrorReadError;
    }
  }

  if (!header_file) {
    XELOGE("Error opening STFS header file.");
    return Error::kErrorReadError;
  }

  auto header_result = ReadHeaderAndVerify(header_file);
  if (header_result != Error::kSuccess) {
    XELOGE("Error reading STFS header: {}", header_result);
    fclose(header_file);
    files_total_size_ = 0;
    return header_result;
  }

  // If the STFS package is a single file, the header is self contained and
  // we don't need to map any extra files.
  // NOTE: data_file_count is 0 for STFS and 1 for SVOD
  if (header_.metadata.data_file_count <= 1) {
    XELOGI("STFS container is a single file.");
    files_.emplace(std::make_pair(0, header_file));
    return Error::kSuccess;
  }

  // If the STFS package is multi-file, it is an SVOD system. We need to map
  // the files in the .data folder and can discard the header.
  auto data_fragment_path = host_path_;
  data_fragment_path += ".data";
  if (!std::filesystem::exists(data_fragment_path)) {
    XELOGE("STFS container is multi-file, but path {} does not exist.",
           xe::path_to_utf8(data_fragment_path));
    return Error::kErrorFileMismatch;
  }

  // Ensure data fragment files are sorted
  auto fragment_files = filesystem::ListFiles(data_fragment_path);
  std::sort(fragment_files.begin(), fragment_files.end(),
            [](filesystem::FileInfo& left, filesystem::FileInfo& right) {
              return left.name < right.name;
            });

  if (fragment_files.size() != header_.metadata.data_file_count) {
    XELOGE("SVOD expecting {} data fragments, but {} are present.",
           header_.metadata.data_file_count, fragment_files.size());
    return Error::kErrorFileMismatch;
  }

  for (size_t i = 0; i < fragment_files.size(); i++) {
    auto fragment = fragment_files.at(i);
    auto path = fragment.path / fragment.name;
    auto file = xe::filesystem::OpenFile(path, "rb");
    if (!file) {
      XELOGI("Failed to map SVOD file {}.", xe::path_to_utf8(path));
      CloseFiles();
      return Error::kErrorReadError;
    }

    xe::filesystem::Seek(file, 0L, SEEK_END);
    files_total_size_ += xe::filesystem::Tell(file);
    // no need to seek back, any reads from this file will seek first anyway
    files_.emplace(std::make_pair(i, file));
  }
  XELOGI("SVOD successfully mapped {} files.", fragment_files.size());
  return Error::kSuccess;
}

void StfsContainerDevice::CloseFiles() {
  if (files_.size()) {
    // Flush any pending STFS writes
    STFSFlush();

    for (auto file : files_) {
      fclose(file.second);
    }
    files_.clear();
    files_total_size_ = 0;
  }
}

StfsContainerDevice::Error StfsContainerDevice::ReadHeaderAndVerify(
    FILE* header_file) {
  // Check if file contains an existing STFS header for us to read
  xe::filesystem::Seek(header_file, 0L, SEEK_END);
  files_total_size_ = xe::filesystem::Tell(header_file);
  xe::filesystem::Seek(header_file, 0L, SEEK_SET);

  if (files_total_size_ >= sizeof(StfsHeader)) {
    // Read header & check signature
    fread(&header_, sizeof(StfsHeader), 1, header_file);

    if (!header_.header.is_magic_valid()) {
      // Unexpected format.
      return Error::kErrorFileMismatch;
    }
  } else {
    header_.set_defaults();
  }

  // Pre-calculate some values used in block number calculations
  if (header_.metadata.volume_type == XContentVolumeType::kStfs) {
    blocks_per_hash_table_ =
        header_.metadata.volume_descriptor.stfs.flags.bits.read_only_format ? 1
                                                                            : 2;

    block_step_[0] = kBlocksPerHashLevel[0] + blocks_per_hash_table_;
    block_step_[1] = kBlocksPerHashLevel[1] +
                     ((kBlocksPerHashLevel[0] + 1) * blocks_per_hash_table_);
  }

  return Error::kSuccess;
}

StfsContainerDevice::Error StfsContainerDevice::ReadSVOD() {
  // SVOD Systems can have different layouts. The root block is
  // denoted by the magic "MICROSOFT*XBOX*MEDIA" and is always in
  // the first "actual" data fragment of the system.
  const char* MEDIA_MAGIC = "MICROSOFT*XBOX*MEDIA";

  uint8_t magic_buf[20];
  uint32_t magic_offset;

  auto svod_header = main_file();
  // Check for EDGF layout
  if (header_.metadata.volume_descriptor.svod.features.bits
          .enhanced_gdf_layout) {
    // The STFS header has specified that this SVOD system uses the EGDF layout.
    // We can expect the magic block to be located immediately after the hash
    // blocks. We also offset block address calculation by 0x1000 by shifting
    // block indices by +0x2.
    xe::filesystem::Seek(svod_header, 0x2000, SEEK_SET);
    fread(magic_buf, 1, 20, svod_header);
    if (memcmp(magic_buf, MEDIA_MAGIC, 20) == 0) {
      svod_base_offset_ = 0x0000;
      magic_offset = 0x2000;
      svod_layout_ = SvodLayoutType::kEnhancedGDF;
      XELOGI("SVOD uses an EGDF layout. Magic block present at 0x2000.");
    } else {
      XELOGE("SVOD uses an EGDF layout, but the magic block was not found.");
      return Error::kErrorFileMismatch;
    }
  } else {
    xe::filesystem::Seek(svod_header, 0x12000, SEEK_SET);
    fread(magic_buf, 1, 20, svod_header);
    if (memcmp(magic_buf, MEDIA_MAGIC, 20) == 0) {
      // If the SVOD's magic block is at 0x12000, it is likely using an XSF
      // layout. This is usually due to converting the game using a third-party
      // tool, as most of them use a nulled XSF as a template.

      svod_base_offset_ = 0x10000;
      magic_offset = 0x12000;

      // Check for XSF Header
      const char* XSF_MAGIC = "XSF";
      xe::filesystem::Seek(svod_header, 0x2000, SEEK_SET);
      fread(magic_buf, 1, 3, svod_header);
      if (memcmp(magic_buf, XSF_MAGIC, 3) == 0) {
        svod_layout_ = SvodLayoutType::kXSF;
        XELOGI("SVOD uses an XSF layout. Magic block present at 0x12000.");
        XELOGI("Game was likely converted using a third-party tool.");
      } else {
        svod_layout_ = SvodLayoutType::kUnknown;
        XELOGI("SVOD appears to use an XSF layout, but no header is present.");
        XELOGI("SVOD magic block found at 0x12000");
      }
    } else {
      xe::filesystem::Seek(svod_header, 0xD000, SEEK_SET);
      fread(magic_buf, 1, 20, svod_header);
      if (memcmp(magic_buf, MEDIA_MAGIC, 20) == 0) {
        // If the SVOD's magic block is at 0xD000, it most likely means that it
        // is a single-file system. The STFS Header is 0xB000 bytes , and the
        // remaining 0x2000 is from hash tables. In most cases, these will be
        // STFS, not SVOD.

        svod_base_offset_ = 0xB000;
        magic_offset = 0xD000;

        // Check for single file system
        if (header_.metadata.data_file_count == 1) {
          svod_layout_ = SvodLayoutType::kSingleFile;
          XELOGI("SVOD is a single file. Magic block present at 0xD000.");
        } else {
          svod_layout_ = SvodLayoutType::kUnknown;
          XELOGE(
              "SVOD is not a single file, but the magic block was found at "
              "0xD000.");
        }
      } else {
        XELOGE("Could not locate SVOD magic block.");
        return Error::kErrorReadError;
      }
    }
  }

  // Parse the root directory
  xe::filesystem::Seek(svod_header, magic_offset + 0x14, SEEK_SET);

  uint32_t root_block;
  uint32_t root_size;
  uint32_t root_creation_date;
  uint32_t root_creation_time;
  fread(&root_block, sizeof(uint32_t), 1, svod_header);
  fread(&root_size, sizeof(uint32_t), 1, svod_header);
  fread(&root_creation_date, sizeof(uint32_t), 1, svod_header);
  fread(&root_creation_time, sizeof(uint32_t), 1, svod_header);

  uint64_t root_creation_timestamp =
      decode_fat_timestamp(root_creation_date, root_creation_time);

  auto root_entry = new StfsContainerEntry(this, nullptr, "", &files_);
  root_entry->attributes_ = kFileAttributeDirectory;
  root_entry->access_timestamp_ = root_creation_timestamp;
  root_entry->create_timestamp_ = root_creation_timestamp;
  root_entry->write_timestamp_ = root_creation_timestamp;
  root_entry_ = std::unique_ptr<Entry>(root_entry);

  // Traverse all child entries
  return ReadEntrySVOD(root_block, 0, root_entry);
}

StfsContainerDevice::Error StfsContainerDevice::ReadEntrySVOD(
    uint32_t block, uint32_t ordinal, StfsContainerEntry* parent) {
  // For games with a large amount of files, the ordinal offset can overrun
  // the current block and potentially hit a hash block.
  size_t ordinal_offset = ordinal * 0x4;
  size_t block_offset = ordinal_offset / 0x800;
  size_t true_ordinal_offset = ordinal_offset % 0x800;

  // Calculate the file & address of the block
  size_t entry_address, entry_file;
  BlockToOffsetSVOD(block + block_offset, &entry_address, &entry_file);
  entry_address += true_ordinal_offset;

  // Read block's descriptor

  auto file = files_.at(entry_file);
  xe::filesystem::Seek(file, entry_address, SEEK_SET);

  uint16_t node_l;
  uint16_t node_r;
  uint32_t data_block;
  uint32_t length;
  uint8_t attributes;
  uint8_t name_length;
  fread(&node_l, sizeof(uint16_t), 1, file);
  fread(&node_r, sizeof(uint16_t), 1, file);
  fread(&data_block, sizeof(uint32_t), 1, file);
  fread(&length, sizeof(uint32_t), 1, file);
  fread(&attributes, sizeof(uint8_t), 1, file);
  fread(&name_length, sizeof(uint8_t), 1, file);

  auto name_buffer = std::make_unique<char[]>(name_length);
  fread(name_buffer.get(), 1, name_length, file);

  auto name = std::string(name_buffer.get(), name_length);

  // Read the left node
  if (node_l) {
    auto node_result = ReadEntrySVOD(block, node_l, parent);
    if (node_result != Error::kSuccess) {
      return node_result;
    }
  }

  // Read file & address of block's data
  size_t data_address, data_file;
  BlockToOffsetSVOD(data_block, &data_address, &data_file);

  // Create the entry
  // NOTE: SVOD entries don't have timestamps for individual files, which can
  //       cause issues when decrypting games. Using the root entry's timestamp
  //       solves this issues.
  auto entry = StfsContainerEntry::Create(this, parent, name, &files_);
  if (attributes & kFileAttributeDirectory) {
    // Entry is a directory
    entry->attributes_ = kFileAttributeDirectory | kFileAttributeReadOnly;
    entry->size_ = 0;
    entry->start_block_ = block;
    entry->access_timestamp_ = root_entry_->create_timestamp();
    entry->create_timestamp_ = root_entry_->create_timestamp();
    entry->write_timestamp_ = root_entry_->create_timestamp();

    if (length) {
      // If length is greater than 0, traverse the directory's children
      auto directory_result = ReadEntrySVOD(data_block, 0, entry.get());
      if (directory_result != Error::kSuccess) {
        return directory_result;
      }
    }
  } else {
    // Entry is a file
    entry->attributes_ = kFileAttributeNormal | kFileAttributeReadOnly;
    entry->size_ = length;
    entry->allocation_size_ = xe::round_up(length, kBlockSize);
    entry->start_block_ = data_block;
    entry->access_timestamp_ = root_entry_->create_timestamp();
    entry->create_timestamp_ = root_entry_->create_timestamp();
    entry->write_timestamp_ = root_entry_->create_timestamp();

    // Fill in all block records, sector by sector.
    if (entry->attributes() & X_FILE_ATTRIBUTE_NORMAL) {
      uint32_t block_index = data_block;
      size_t remaining_size = xe::round_up(length, 0x800);

      size_t last_record = -1;
      size_t last_offset = -1;
      while (remaining_size) {
        const size_t BLOCK_SIZE = 0x800;

        size_t offset, file_index;
        BlockToOffsetSVOD(block_index, &offset, &file_index);

        block_index++;
        remaining_size -= BLOCK_SIZE;

        if (offset - last_offset == 0x800) {
          // Consecutive, so append to last entry.
          entry->block_list_[last_record].length += BLOCK_SIZE;
          last_offset = offset;
          continue;
        }

        entry->block_list_.push_back({file_index, offset, BLOCK_SIZE});
        last_record = entry->block_list_.size() - 1;
        last_offset = offset;
      }
    }
  }

  parent->children_.emplace_back(std::move(entry));

  // Read the right node.
  if (node_r) {
    auto node_result = ReadEntrySVOD(block, node_r, parent);
    if (node_result != Error::kSuccess) {
      return node_result;
    }
  }

  return Error::kSuccess;
}

void StfsContainerDevice::BlockToOffsetSVOD(size_t block, size_t* out_address,
                                            size_t* out_file_index) {
  // SVOD Systems use hash blocks for integrity checks. These hash blocks
  // cause blocks to be discontinuous in memory, and must be accounted for.
  //  - Each data block is 0x800 bytes in length
  //  - Every group of 0x198 data blocks is preceded a Level0 hash table.
  //    Level0 tables contain 0xCC hashes, each representing two data blocks.
  //    The total size of each Level0 hash table is 0x1000 bytes in length.
  //  - Every 0xA1C4 Level0 hash tables is preceded by a Level1 hash table.
  //    Level1 tables contain 0xCB hashes, each representing two Level0 hashes.
  //    The total size of each Level1 hash table is 0x1000 bytes in length.
  //  - Files are split into fragments of 0xA290000 bytes in length,
  //    consisting of 0x14388 data blocks, 0xCB Level0 hash tables, and 0x1
  //    Level1 hash table.

  const size_t BLOCK_SIZE = 0x800;
  const size_t HASH_BLOCK_SIZE = 0x1000;
  const size_t BLOCKS_PER_L0_HASH = 0x198;
  const size_t HASHES_PER_L1_HASH = 0xA1C4;
  const size_t BLOCKS_PER_FILE = 0x14388;
  const size_t MAX_FILE_SIZE = 0xA290000;
  const size_t BLOCK_OFFSET =
      header_.metadata.volume_descriptor.svod.start_data_block();

  // Resolve the true block address and file index
  size_t true_block = block - (BLOCK_OFFSET * 2);
  if (svod_layout_ == SvodLayoutType::kEnhancedGDF) {
    // EGDF has an 0x1000 byte offset, which is two blocks
    true_block += 0x2;
  }

  size_t file_block = true_block % BLOCKS_PER_FILE;
  size_t file_index = true_block / BLOCKS_PER_FILE;
  size_t offset = 0;

  // Calculate offset caused by Level0 Hash Tables
  size_t level0_table_count = (file_block / BLOCKS_PER_L0_HASH) + 1;
  offset += level0_table_count * HASH_BLOCK_SIZE;

  // Calculate offset caused by Level1 Hash Tables
  size_t level1_table_count = (level0_table_count / HASHES_PER_L1_HASH) + 1;
  offset += level1_table_count * HASH_BLOCK_SIZE;

  // For single-file SVOD layouts, include the size of the header in the offset.
  if (svod_layout_ == SvodLayoutType::kSingleFile) {
    offset += svod_base_offset_;
  }

  size_t block_address = (file_block * BLOCK_SIZE) + offset;

  // If the offset causes the block address to overrun the file, round it.
  if (block_address >= MAX_FILE_SIZE) {
    file_index += 1;
    block_address %= MAX_FILE_SIZE;
    block_address += 0x2000;
  }

  *out_address = block_address;
  *out_file_index = file_index;
}

bool StfsContainerDevice::STFSFlush() {
  if (is_read_only()) {
    return false;  // package is read-only, can't update anything
  }
  auto& descriptor = header_.metadata.volume_descriptor.stfs;
  auto package_file = main_file();

  // Seek to final allocated block, this should ensure enough space is allocated
  // for everything?
  xe::filesystem::Seek(package_file,
                       STFSDataBlockToOffset(descriptor.total_block_count + 1),
                       SEEK_SET);

  // Write out directory entries
  STFSWriteDirectory();

  // Sanity check
  if (descriptor.total_block_count > kBlocksPerHashLevel[2]) {
    XELOGE(
        "XContentDevice::Flush: too many blocks in package! {} blocks, STFS "
        "allows maximum of {}!",
        descriptor.total_block_count, kBlocksPerHashLevel[2]);
  }

  // Fix hashes of any dirty blocks
  uint8_t block_buf[0x1000];

  // TODO: rework this so that hashed_offsets list isn't needed
  // (atm it might try hashing the same hash-block multiple times, if any dirty
  // blocks share the same hash-block)
  std::vector<uint64_t> hashed_offsets;
  for (uint32_t hash_level = 0; hash_level <= STFSMaxHashLevel();
       hash_level++) {
    for (auto block_num : dirty_blocks_) {
      auto block_offset = hash_level == 0 ? STFSDataBlockToOffset(block_num)
                                          : STFSDataBlockToHashBlockOffset(
                                                block_num, hash_level);

      if (std::find(hashed_offsets.begin(), hashed_offsets.end(),
                    block_offset) != hashed_offsets.end()) {
        continue;  // already hashed this table/block
      }

      auto entry_num = block_num;
      if (hash_level > 0) {
        entry_num = entry_num / kBlocksPerHashLevel[hash_level - 1];
      }
      entry_num = entry_num % kBlocksPerHashLevel[0];

      auto& hash_table = hash_level == 0
                             ? STFSGetDataHashTable(block_num, nullptr)
                             : STFSGetHashTable(block_num, hash_level, nullptr,
                                                false, nullptr);

      auto& entry = hash_table.entries[entry_num];

      xe::filesystem::Seek(package_file, block_offset, SEEK_SET);
      fread(block_buf, 1, 0x1000, package_file);

      sha1::SHA1 sha;
      sha.processBytes(block_buf, 0x1000);
      sha.finalize(entry.sha1);

      hashed_offsets.push_back(block_offset);
    }
  }

  dirty_blocks_.clear();

  // Write out the hash tables
  for (const auto& table : hash_tables_) {
    xe::filesystem::Seek(package_file, table.first, SEEK_SET);
    fwrite(&table.second, sizeof(table.second), 1, package_file);
  }

  // Update top-hash-level hash
  xe::filesystem::Seek(package_file,
                       STFSDataBlockToHashBlockOffset(0, STFSMaxHashLevel()),
                       SEEK_SET);
  fread(block_buf, 1, 0x1000, package_file);

  sha1::SHA1 sha;
  sha.processBytes(block_buf, 0x1000);
  sha.finalize(header_.metadata.volume_descriptor.stfs.top_hash_table_hash);

  // Update XContent header
  xe::filesystem::Seek(package_file, 0, SEEK_SET);
  fwrite(&header_, sizeof(header_), 1, package_file);

  // Finish with a fflush
  fflush(package_file);

  return true;
}

void StfsContainerDevice::FlattenChildEntries(
    StfsContainerEntry* entry, std::vector<StfsContainerEntry*>* entry_list) {
  for (auto& child : entry->children_) {
    auto* child_entry = reinterpret_cast<StfsContainerEntry*>(child.get());
    entry_list->push_back(child_entry);
    FlattenChildEntries(child_entry, entry_list);
  }
}

void StfsContainerDevice::STFSWriteDirectory() {
  auto& descriptor = header_.metadata.volume_descriptor.stfs;

  if (descriptor.flags.bits.read_only_format) {
    // Read-only package.
    return;
  }

  if (root_entry_ == nullptr) {
    // Something bad happened during load?
    assert_always();
    return;
  }

  auto package_file = main_file();

  std::vector<StfsContainerEntry*> all_entries;
  FlattenChildEntries(reinterpret_cast<StfsContainerEntry*>(root_entry_.get()),
                      &all_entries);

  auto num_blocks =
      bytes_to_stfs_blocks(all_entries.size() * sizeof(StfsDirectoryEntry));

  auto directory_block = descriptor.file_table_block_number();

  // We could skip STFSBlockAllocate if num_blocks <= 0, but it's good to always
  // make sure directory has a block
  if (descriptor.file_table_block_count <= 0) {
    directory_block = STFSBlockAllocate();
    descriptor.set_file_table_block_number(directory_block);
    descriptor.file_table_block_count = 1;
  }

  if (!num_blocks) {
    // Nothing to write, exit out for now
    return;
  }

  descriptor.file_table_block_count = uint16_t(num_blocks);

  auto directory_chain = STFSResizeDataBlockChain(directory_block, num_blocks);

  for (uint32_t block_idx = 0; block_idx < num_blocks; block_idx++) {
    auto cur_block = directory_chain[block_idx];
    auto cur_entry = block_idx * kEntriesPerDirectoryBlock;
    auto end_entry = std::min(size_t(kEntriesPerDirectoryBlock),
                              all_entries.size() - cur_entry);

    StfsDirectoryBlock directory = {0};
    for (uint32_t entry_idx = 0; entry_idx < end_entry; entry_idx++) {
      auto& entry = all_entries[entry_idx + cur_entry];
      auto& dir_entry = directory.entries[entry_idx];

      auto name_str = entry->name_;
      if (name_str.length() > countof(dir_entry.name)) {
        name_str.resize(countof(dir_entry.name));
      }

      strcpy_s(dir_entry.name, name_str.c_str());
      dir_entry.flags.name_length = name_str.length();

      dir_entry.flags.directory =
          (entry->attributes_ & kFileAttributeDirectory);

      dir_entry.length = uint32_t(entry->size_);

      auto [create_date, create_time] =
          encode_fat_timestamp(entry->create_timestamp_);
      dir_entry.create_date = create_date;
      dir_entry.create_time = create_time;

      auto [modified_date, modified_time] =
          encode_fat_timestamp(entry->write_timestamp_);
      dir_entry.modified_date = modified_date;
      dir_entry.modified_time = modified_time;

      dir_entry.set_start_block_number(entry->start_block_);
      dir_entry.set_allocated_data_blocks(uint32_t(entry->block_list_.size()));
      dir_entry.set_valid_data_blocks(dir_entry.allocated_data_blocks());

      if (entry->parent_ && entry->parent_ != root_entry_.get()) {
        uint32_t parent = -1;
        for (uint32_t n = 0; n < all_entries.size(); n++) {
          if (all_entries[n] == entry->parent_) {
            parent = n;
            break;
          }
        }
        if (parent == -1) {
          XELOGE(
              "XContent: failed to locate parent entry in all_entries list, "
              "this shouldn't happen!");
          assert_always();
          parent = 0xFFFF;
        }
        dir_entry.directory_index = uint16_t(parent);
      } else {
        dir_entry.directory_index = 0xFFFF;
      }
    }

    bool write_block = true;
    // If block isn't already marked as dirty (via BlockAllocate etc), check
    // hash to see if we actually need to mark it so
    //
    // (this way hash tables won't need to be needlessly recalculated when data
    // hasn't even changed)
    if (!STFSBlockIsMarkedDirty(cur_block)) {
      auto& cur_hash_entry = STFSGetDataHashEntry(cur_block);

      uint8_t cur_data_hash[0x14];
      sha1::SHA1 sha;
      sha.processBytes(&directory, sizeof(directory));
      sha.finalize(cur_data_hash);

      if (!memcmp(cur_hash_entry.sha1, cur_data_hash, 0x14)) {
        // Data hasn't changed, no need to write block or mark dirty!
        write_block = false;
      }
    }

    if (write_block) {
      xe::filesystem::Seek(package_file, STFSDataBlockToOffset(cur_block),
                           SEEK_SET);
      fwrite(&directory, sizeof(directory), 1, package_file);
      STFSBlockMarkDirty(cur_block);
    }
  }
}

bool StfsContainerDevice::STFSReadDirectory() {
  auto root_entry = new StfsContainerEntry(this, nullptr, "", &files_);
  root_entry->attributes_ = kFileAttributeDirectory;
  root_entry_ = std::unique_ptr<Entry>(root_entry);

  auto& descriptor = header_.metadata.volume_descriptor.stfs;

  if (descriptor.file_table_block_count == 0) {
    // Check if we've just created a new container, allocate a dir block if so
    // (this isn't really necessary, we could handle dir block allocating when
    // saving, which would put dir blocks after data blocks, but X360 packages
    // usually have dir blocks before data blocks, so guess they probably do
    // something similar to here)
    if (descriptor.total_block_count == 0 && allow_creating_) {
      STFSWriteDirectory();
      return true;
    }
    XELOGFS("XContent: file_table_block_count = 0, skipping ReadDirectory");
    return true;  // no files to read!
  }

  auto table_chain =
      STFSGetDataBlockChain(descriptor.file_table_block_number(),
                            descriptor.file_table_block_count +
                                5);  // plus 5 in case descriptor is incorrect

  if (table_chain.size() != descriptor.file_table_block_count) {
    XELOGW(
        "XContent: found {} STFS file table blocks, but STFS headers expected "
        "{}!",
        table_chain.size(), descriptor.file_table_block_count);
  }

  auto file = main_file();

  StfsDirectoryBlock directory;
  std::vector<StfsContainerEntry*> all_entries;
  for (auto table_cur_block : table_chain) {
    uint64_t cur_offset = STFSDataBlockToOffset(table_cur_block);
    xe::filesystem::Seek(file, cur_offset, SEEK_SET);
    fread(&directory, sizeof(directory), 1, file);

    for (auto cur_entry = 0; cur_entry < countof(directory.entries);
         cur_entry++) {
      auto& dir_entry = directory.entries[cur_entry];
      if (dir_entry.name[0] == 0) {
        // finished with this block
        continue;
      }

      StfsContainerEntry* parent_entry = nullptr;
      if (dir_entry.directory_index == 0xFFFF) {
        parent_entry = root_entry;
      } else {
        parent_entry = all_entries[dir_entry.directory_index];
      }

      std::string name(reinterpret_cast<const char*>(dir_entry.name),
                       dir_entry.flags.name_length & 0x3F);
      auto entry =
          StfsContainerEntry::Create(this, parent_entry, name, &files_);

      entry->attributes_ = dir_entry.flags.directory ? kFileAttributeDirectory
                                                     : kFileAttributeNormal;
      if (descriptor.flags.bits.read_only_format) {
        entry->attributes_ |= kFileAttributeReadOnly;
      }

      entry->size_ = dir_entry.length;
      entry->allocation_size_ = xe::round_up(dir_entry.length, kBlockSize);

      entry->create_timestamp_ =
          decode_fat_timestamp(dir_entry.create_date, dir_entry.create_time);
      entry->write_timestamp_ = decode_fat_timestamp(dir_entry.modified_date,
                                                     dir_entry.modified_time);
      entry->access_timestamp_ = entry->write_timestamp_;

      entry->start_block_ = dir_entry.start_block_number();

      all_entries.push_back(entry.get());

      // Preload block list for this entry
      if (!dir_entry.flags.directory) {
        entry->UpdateBlockList();

        // Check that the number of blocks retrieved from hash entries matches
        // the block count read from the file entry
        if (entry->block_list_.size() != dir_entry.allocated_data_blocks()) {
          XELOGW(
              "XContent: failed to read correct block-chain for entry {}, "
              "read {} blocks, expected {}",
              entry->name_, entry->block_list_.size(),
              dir_entry.allocated_data_blocks());
          assert_always();
        }
      }
      parent_entry->children_.emplace_back(std::move(entry));
    }
  }
  XELOGFS("XContent: read {} files from package", all_entries.size());

  return true;
}

std::vector<uint32_t> StfsContainerDevice::STFSGetDataBlockChain(
    uint32_t block_num, uint32_t max_count) {
  std::vector<uint32_t> block_chain;

  uint32_t cur_block = block_num;
  for (uint32_t cur_idx = 0; cur_idx < max_count; cur_idx++) {
    block_chain.push_back(cur_block);
    auto hash_entry = STFSGetDataHashEntry(cur_block);

    if (hash_entry.level0_next_block() == kEndOfChain) {
      break;
    }
    cur_block = hash_entry.level0_next_block();
  }

  return block_chain;
}

void StfsContainerDevice::STFSSetDataBlockChain(
    const std::vector<uint32_t>& chain) {
  // TODO: this should handle blocks being removed from the current chain &
  // de-allocate them properly...
  // STFSResizeDataBlockChain can do that for most cases though
  for (auto it = chain.rbegin(); it != chain.rend(); it++) {
    auto hash_entry = STFSGetDataHashEntry(*it);
    if (it == chain.rbegin()) {
      hash_entry.set_level0_next_block(kEndOfChain);
    } else {
      auto prev = it - 1;
      hash_entry.set_level0_next_block(*prev);
    }
    STFSSetDataHashEntry(*it, hash_entry);
  }
}

std::vector<uint32_t> StfsContainerDevice::STFSResizeDataBlockChain(
    uint32_t start_block, uint32_t num_blocks) {
  auto block_chain = STFSGetDataBlockChain(start_block);
  if (is_read_only()) {
    return block_chain;
  }

  bool chain_updated = false;
  if (num_blocks > block_chain.size()) {
    for (auto n = block_chain.size(); n < num_blocks; n++) {
      auto block = STFSBlockAllocate();
      block_chain.push_back(block);
    }
    chain_updated = true;
  } else if (num_blocks < block_chain.size()) {
    for (uint32_t n = num_blocks; n < block_chain.size(); n++) {
      STFSBlockFree(block_chain[n]);
    }
    block_chain.resize(num_blocks);
    chain_updated = true;
  }

  if (chain_updated && block_chain.size() > 0) {
    STFSSetDataBlockChain(block_chain);
  }

  return block_chain;
}

uint64_t StfsContainerDevice::STFSDataBlockToOffset(uint32_t block_num) const {
  // For every level there is a hash table
  // Level 0: hash table of next 170 blocks
  // Level 1: hash table of next 170 hash tables
  // Level 2: hash table of next 170 level 1 hash tables
  // And so on...
  uint64_t base = kBlocksPerHashLevel[0];
  uint64_t block = block_num;
  for (uint32_t i = 0; i < 3; i++) {
    block += ((block_num + base) / base) * blocks_per_hash_table_;
    if (block_num < base) {
      break;
    }

    base *= kBlocksPerHashLevel[0];
  }

  return xe::round_up(header_.header.header_size, kBlockSize) +
         (block * kBlockSize);
}

uint32_t StfsContainerDevice::STFSDataBlockToHashBlockNum(
    uint32_t block_num, uint32_t hash_level) const {
  uint32_t block = 0;
  if (hash_level == 0) {
    if (block_num < kBlocksPerHashLevel[0]) {
      return 0;
    }

    block = (block_num / kBlocksPerHashLevel[0]) * block_step_[0];
    block +=
        ((block_num / kBlocksPerHashLevel[1]) + 1) * blocks_per_hash_table_;

    if (block_num < kBlocksPerHashLevel[1]) {
      return block;
    }

    return block + blocks_per_hash_table_;
  }

  if (hash_level == 1) {
    if (block_num < kBlocksPerHashLevel[1]) {
      return block_step_[0];
    }

    block = (block_num / kBlocksPerHashLevel[1]) * block_step_[1];
    return block + blocks_per_hash_table_;
  }

  // Level 2 is always at blockStep1
  return block_step_[1];
}

uint64_t StfsContainerDevice::STFSDataBlockToHashBlockOffset(
    uint32_t block_num, uint32_t hash_level) const {
  auto hash_block = STFSDataBlockToHashBlockNum(block_num, hash_level);

  return xe::round_up(header_.header.header_size, kBlockSize) +
         (hash_block * kBlockSize);
};

StfsHashTable& StfsContainerDevice::STFSGetHashTable(uint32_t block_num,
                                                     uint32_t hash_level,
                                                     uint8_t* hash_in_out,
                                                     bool use_secondary_block,
                                                     bool* is_table_invalid) {
  uint64_t table_key = STFSDataBlockToHashBlockOffset(block_num, hash_level);

  // Keep original offset to use as hash_tables_ key, so we can treat both
  // primary block & secondary block as a single table
  uint64_t table_offset = table_key;

  // Read from the tables secondary block if requested (and this package
  // supports them)
  if (use_secondary_block && blocks_per_hash_table_ > 1) {
    table_offset += kBlockSize;
  }

  // Check if we've already marked this as invalid or not (use actual offset to
  // be sure)
  bool invalid_table = std::find(invalid_tables_.begin(), invalid_tables_.end(),
                                 table_offset) != invalid_tables_.end();

  if (!hash_tables_.count(table_key)) {
    // Read table into memory since it's likely to be used more than once
    StfsHashTable hash_table = {0};

    auto package_file = main_file();
    xe::filesystem::Seek(package_file, table_offset, SEEK_SET);
    fread(&hash_table, sizeof(hash_table), 1, package_file);

    hash_tables_[table_key] = hash_table;

    // If hash is provided we'll try comparing it to the hash of this table
    if (hash_in_out && !invalid_table) {
      sha1::SHA1 sha;
      sha.processBytes(&hash_table, kBlockSize);

      uint8_t digest[0x14];
      sha.finalize(digest);
      if (memcmp(digest, hash_in_out, 0x14)) {
        XELOGW(
            "STFSGetHashEntry: level %d hash table at 0x%llX "
            "is corrupt (hash mismatch)!",
            hash_level, table_offset);
        invalid_table = true;
        invalid_tables_.push_back(table_offset);
      }
    }
  }

  if (is_table_invalid) {
    *is_table_invalid = invalid_table;
  }
  return hash_tables_[table_key];
}

StfsHashEntry& StfsContainerDevice::STFSGetHashEntry(uint32_t block_num,
                                                     uint32_t hash_level,
                                                     uint8_t* hash_in_out,
                                                     bool use_secondary_block) {
  bool invalid_table = false;
  auto hash_table = STFSGetHashTable(block_num, hash_level, hash_in_out,
                                     use_secondary_block, &invalid_table);

  uint32_t entry_num = block_num;
  if (hash_level > 0) {
    entry_num = entry_num / kBlocksPerHashLevel[hash_level - 1];
  }
  entry_num = entry_num % kBlocksPerHashLevel[0];

  auto& entry = hash_table.entries[entry_num];
  if (hash_in_out) {
    // Copy entry hash to output param
    memcpy(hash_in_out, entry.sha1, countof(entry.sha1));
  }
  return entry;
}

StfsHashTable& StfsContainerDevice::STFSGetDataHashTable(
    uint32_t block_num, bool* is_table_invalid) {
  auto& descriptor = header_.metadata.volume_descriptor;

  bool use_secondary_block = false;
  // Use root table's secondary block if RootActiveIndex flag is set
  if (descriptor.stfs.flags.bits.root_active_index &&
      blocks_per_hash_table_ > 1) {
    use_secondary_block = true;
    // Unset root_active_index as any hash-tables we write out will write to
    // primary block
    descriptor.stfs.flags.bits.root_active_index = false;
  }

  // Copy our top hash table hash into a temp buffer
  uint8_t hash[0x14];
  memcpy(hash, descriptor.stfs.top_hash_table_hash, 0x14);

  // Check upper hash table levels to find which table (primary/secondary) to
  // use.

  // At one point this would always skip this if package is read-only, but it
  // seems there's a lot of LIVE/PIRS packages with corrupt hash tables out
  // there, checking the hash table hashes is the only way to detect (and then
  // possibly salvage) these...
  auto num_blocks = descriptor.stfs.total_block_count;

  if (num_blocks >= kBlocksPerHashLevel[1]) {
    // Get the L2 entry for the block
    auto l2_entry = STFSGetHashEntry(block_num, 2, hash, use_secondary_block);
    use_secondary_block = false;
    if (l2_entry.levelN_active_index() && blocks_per_hash_table_ > 1) {
      use_secondary_block = true;

      // Unset root_active_index as any hash-tables we write out will write to
      // primary block
      l2_entry.set_levelN_active_index(false);
    }
  }

  if (num_blocks >= kBlocksPerHashLevel[0]) {
    // Get the L1 entry for this block
    auto l1_entry = STFSGetHashEntry(block_num, 1, hash, use_secondary_block);
    use_secondary_block = false;
    if (l1_entry.levelN_active_index() && blocks_per_hash_table_ > 1) {
      use_secondary_block = true;

      // Unset root_active_index as any hash-tables we write out will write to
      // primary block
      l1_entry.set_levelN_active_index(false);
    }
  }

  return STFSGetHashTable(block_num, 0, hash, use_secondary_block,
                          is_table_invalid);
}

StfsHashEntry StfsContainerDevice::STFSGetDataHashEntry(uint32_t block_num) {
  bool invalid_table = false;
  const auto& table = STFSGetDataHashTable(block_num, &invalid_table);

  if (invalid_table &&
      header_.metadata.volume_descriptor.stfs.flags.bits.read_only_format) {
    // Table is invalid, likely means we can't trust any next_block pointers or
    // anything like that..
    // Try salvaging the package by providing entry as next_block = cur_block
    // + 1, should help with LIVE/PIRS at least.
    StfsHashEntry entry = {0};
    entry.set_level0_next_block(block_num + 1);
    return entry;
  }
  if (invalid_table) {
    XELOGW("STFS: hash table for block {} has bad hash, likely invalid!",
           block_num);
  }
  auto entry_num = block_num % kBlocksPerHashLevel[0];
  return table.entries[entry_num];
}

void StfsContainerDevice::STFSSetDataHashEntry(
    uint32_t block_num, const StfsHashEntry& hash_entry) {
  if (is_read_only()) {
    return;
  }

  auto& table = STFSGetDataHashTable(block_num, nullptr);

  auto entry_num = block_num % kBlocksPerHashLevel[0];
  table.entries[entry_num] = hash_entry;

  // Mark dirty block so upper hash levels can be updated
  STFSBlockMarkDirty(block_num);
}

void StfsContainerDevice::STFSBlockMarkDirty(uint32_t block_num) {
  bool already_exists = std::find(dirty_blocks_.begin(), dirty_blocks_.end(),
                                  block_num) != dirty_blocks_.end();
  if (!already_exists) {
    dirty_blocks_.push_back(block_num);
  }
}

bool StfsContainerDevice::STFSBlockIsMarkedDirty(uint32_t block_num) const {
  return std::find(dirty_blocks_.begin(), dirty_blocks_.end(), block_num) !=
         dirty_blocks_.end();
}

void StfsContainerDevice::STFSBlockFree(uint32_t block_num) {
  if (is_read_only()) {
    return;  // can't modify read-only package!
  }

  auto hash_table = STFSGetDataHashTable(block_num, nullptr);
  auto entry_num = block_num % kBlocksPerHashLevel[0];
  auto& entry = hash_table.entries[entry_num];
  entry.set_level0_allocation_state(StfsHashState::kFree);
  entry.set_level0_next_block(kEndOfChain);
  STFSBlockMarkDirty(block_num);

  header_.metadata.volume_descriptor.stfs.free_block_count++;
}

uint32_t StfsContainerDevice::STFSBlockAllocate() {
  if (is_read_only()) {
    return -1;  // can't modify read-only package!
  }

  auto& descriptor = header_.metadata.volume_descriptor.stfs;
  if (descriptor.free_block_count > 0) {
    // Apparently we have an unused block already allocated, hunt it down...

    uint32_t cur_block = 0;
    while (cur_block < descriptor.total_block_count) {
      auto hash_table = STFSGetDataHashTable(cur_block, nullptr);

      uint32_t blocks_remain = descriptor.total_block_count - cur_block;
      uint32_t blocks_in_table =
          std::min(blocks_remain, kBlocksPerHashLevel[0]);

      for (uint32_t n = 0; n < blocks_in_table; n++) {
        auto& entry = hash_table.entries[n];
        if (entry.level0_allocation_state() != StfsHashState::kInUse) {
          entry.set_level0_allocation_state(StfsHashState::kInUse);
          entry.set_level0_next_block(kEndOfChain);

          uint32_t block_num = cur_block + n;
          STFSBlockMarkDirty(block_num);
          descriptor.free_block_count--;
          return block_num;
        }
      }

      cur_block += kBlocksPerHashLevel[0];
    }
  }

  // No unused blocks available, need to add new one ourselves...
  uint32_t block_num = descriptor.total_block_count++;

  // Allocate space for the new block
  xe::filesystem::Seek(main_file(), STFSDataBlockToOffset(block_num), SEEK_SET);

  // Set new block hash entry, will also mark block as dirty
  StfsHashEntry entry = {0};
  entry.set_level0_allocation_state(StfsHashState::kInUse);
  entry.set_level0_next_block(kEndOfChain);
  STFSSetDataHashEntry(block_num, entry);

  return block_num;
}

}  // namespace vfs
}  // namespace xe
