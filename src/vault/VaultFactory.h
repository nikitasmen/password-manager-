#ifndef VAULT_FACTORY_H
#define VAULT_FACTORY_H

#include <memory>

#include "../config/GlobalConfig.h"
#include "VaultService.h"

// Wires the stores from config: always <dataPath>/vault.json, plus the ESP32 when espHost is set.
std::unique_ptr<VaultService> makeVaultService(const AppConfig& config);

#endif  // VAULT_FACTORY_H
