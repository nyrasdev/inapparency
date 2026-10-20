#include "inapparency/platform/sdcard.hpp"

#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

namespace inapparency::platform {

esp_err_t mount_sd_card(const SdCardConfig& config) {
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();

    spi_bus_config_t bus = {};
    bus.mosi_io_num = config.mosi_gpio;
    bus.miso_io_num = config.miso_gpio;
    bus.sclk_io_num = config.sck_gpio;
    bus.quadwp_io_num = -1;
    bus.quadhd_io_num = -1;
    bus.max_transfer_sz = 4000;
    esp_err_t err =
        spi_bus_initialize(static_cast<spi_host_device_t>(host.slot), &bus, SDSPI_DEFAULT_DMA);
    if (err != ESP_OK) {
        return err;
    }

    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.gpio_cs = static_cast<gpio_num_t>(config.cs_gpio);
    slot.host_id = static_cast<spi_host_device_t>(host.slot);

    esp_vfs_fat_mount_config_t mount = {};
    mount.format_if_mount_failed = false; // never wipe someone's card
    mount.max_files = 2;
    mount.allocation_unit_size = 16 * 1024;

    sdmmc_card_t* card = nullptr;
    err = esp_vfs_fat_sdspi_mount(kSdMountPoint, &host, &slot, &mount, &card);
    if (err != ESP_OK) {
        spi_bus_free(static_cast<spi_host_device_t>(host.slot));
    }
    return err;
}

} // namespace inapparency::platform
