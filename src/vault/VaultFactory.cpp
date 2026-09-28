#include "VaultFactory.h"

#include "EspStore.h"
#include "LocalFileStore.h"

std::unique_ptr<VaultService> makeVaultService(const AppConfig& config) {
    auto local = std::make_unique<LocalFileStore>(config.dataPath + "/vault.json");
    std::unique_ptr<IVaultStore> remote;
    if (!config.espHost.empty())
        remote = std::make_unique<EspStore>(EspConfig{config.espHost, config.espPort, config.espCert, config.espClientCert, config.espClientKey});
    return std::make_unique<VaultService>(std::move(local), std::move(remote), config.dataPath + "/sync.json");
}
