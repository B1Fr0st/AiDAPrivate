#pragma once

/*
 * driver_loader.hpp
 *
 * Provides automatic kernel driver loading for the AiDA plugin.
 * Embeds the WhosWho kernel driver and the P2C vulnerable loader driver
 * as XOR-encrypted byte arrays inside AiDA.dll. At plugin init time,
 * decrypts the blobs in memory, performs the CI-callback exploit via the
 * vulnerable driver, loads WhosWho via NtLoadDriver, then securely wipes
 * all temp artifacts. Neither the mapper EXE nor the driver .sys files
 * are distributed as separate files -- only AiDA.dll ships.
 *
 * Windows-only (guarded by __NT__).
 */

#ifdef __NT__

namespace driver_loader {

/// Attempt to load the WhosWho kernel driver.
/// Returns true if the driver is already loaded or was successfully loaded.
/// Returns false on failure (logged via IDA msg()).
/// Must be called from the IDA main thread during plugin init.
bool initialize_and_load();

/// Returns true if the WhosWho driver device is currently reachable.
bool is_driver_loaded();

}  // namespace driver_loader

#endif  // __NT__
