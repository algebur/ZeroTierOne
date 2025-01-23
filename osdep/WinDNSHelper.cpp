#include "WinDNSHelper.hpp"

#include <IPHlpApi.h>
#include <string>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <locale>
#include <memory>
#include <unordered_map>
#include <Windows.h>
#include <filesystem>

#pragma comment(lib, "IPHlpApi.lib")

namespace ZeroTier {

// Cache for tracking DNS configuration status for each nwid
std::unordered_map<uint64_t, bool> dnsConfiguredForNwid;

// Cache for storing interface names mapped to nwid
std::unordered_map<uint64_t, std::string> interfaceNameCache;

// Maximum size of the log file in bytes (5 MB)
constexpr std::size_t MAX_LOG_FILE_SIZE = 5 * 1024 * 1024;

/**
 * Logs a message to a file.
 * - Checks the size of the log file and truncates it if it exceeds the maximum size.
 * - Appends the provided message to the log file.
 */
void logToFile(const std::string& message)
{
    const std::string logFilePath = "C:\\ProgramData\\ZeroTier\\One\\WinDNSHelper.log";

    // Check file size and truncate if necessary
    try {
        if (std::filesystem::exists(logFilePath) &&
            std::filesystem::file_size(logFilePath) >= MAX_LOG_FILE_SIZE) {
            // If file exceeds the size limit, clear it
            std::ofstream clearFile(logFilePath, std::ios::trunc);
            clearFile.close();
            logToFile("Log file size exceeded the limit. File was cleared.");
        }
    } catch (const std::exception& e) {
        // Log errors related to file size checking
        std::cerr << "Error checking log file size: " << e.what() << std::endl;
    }

    // Append the message to the log file
    std::ofstream logFile(logFilePath, std::ios_base::app);

    if (logFile.is_open()) {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        logFile << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << ": " << message << std::endl;
    }
}

/**
 * Converts a 64-bit integer (nwid) to a hexadecimal string.
 */
std::string nwidToHex(uint64_t nwid)
{
    std::ostringstream ss;
    ss << std::hex << nwid;
    return ss.str();
}

/**
 * Retrieves the name of the TAP adapter associated with a given nwid.
 * - Uses caching to avoid redundant system calls.
 * - If the interface name is not in the cache, it searches for it via system API.
 */
std::string getTapAdapterName(uint64_t nwid)
{
    // Check if the interface name is cached
    if (interfaceNameCache.find(nwid) != interfaceNameCache.end()) {
        logToFile("Using cached TAP adapter name for nwid: " + nwidToHex(nwid));
        return interfaceNameCache[nwid];
    }

    ULONG outBufLen = 0;
    std::unique_ptr<IP_ADAPTER_ADDRESSES, decltype(&free)> pAddresses(nullptr, free);

    // Determine the buffer size needed
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &outBufLen) != ERROR_BUFFER_OVERFLOW) {
        logToFile("Failed to retrieve buffer size for adapter addresses.");
        throw std::runtime_error("Failed to retrieve buffer size for adapter addresses");
    }

    // Allocate memory for adapter addresses
    pAddresses.reset(reinterpret_cast<PIP_ADAPTER_ADDRESSES>(malloc(outBufLen)));
    if (!pAddresses) {
        logToFile("Memory allocation failed for adapter addresses.");
        throw std::runtime_error("Memory allocation failed for adapter addresses");
    }

    std::string hexNwid = nwidToHex(nwid);
    logToFile("Searching for TAP adapter with nwid (hex): " + hexNwid);

    // Retry searching for the adapter up to 5 times
    for (int i = 0; i < 5; ++i) {
        logToFile("Attempt " + std::to_string(i + 1) + ": Searching for TAP adapter...");
        if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddresses.get(), &outBufLen) == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses.get(); pCurrAddresses != nullptr; pCurrAddresses = pCurrAddresses->Next) {
                std::wstring ws(pCurrAddresses->FriendlyName);
                std::string friendlyName(ws.begin(), ws.end());
                logToFile("Found adapter: FriendlyName=" + friendlyName);

                if (friendlyName.find(hexNwid) != std::string::npos) {
                    logToFile("Matched TAP adapter: " + friendlyName);
                    interfaceNameCache[nwid] = friendlyName; // Cache the interface name
                    return friendlyName;
                }
            }
        }
        logToFile("TAP adapter not found, retrying...");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    logToFile("Unable to find TAP adapter for nwid: " + hexNwid);
    throw std::runtime_error("Unable to find TAP adapter for nwid " + hexNwid);
}

/**
 * Executes a PowerShell command.
 * - Logs the command and its output.
 * - Returns true if the command executes successfully.
 */
bool executePowerShellCommand(const std::string& command)
{
    std::ostringstream psCommand;
    psCommand << "powershell.exe -Command \"" << command << "\"";
    logToFile("Executing PowerShell command: " + psCommand.str());

    FILE* pipe = _popen(psCommand.str().c_str(), "r");
    if (!pipe) {
        logToFile("Failed to execute PowerShell command.");
        return false;
    }

    char buffer[128];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    int retCode = _pclose(pipe);

    logToFile("PowerShell command output: " + result);
    logToFile("PowerShell command returned code: " + std::to_string(retCode));

    return retCode == 0;
}

/**
 * Configures the DNS settings for the given nwid.
 * - Avoids redundant configuration by using a status cache.
 * - Sets the static DNS and connection-specific suffix.
 */
void WinDNSHelper::setDNS(uint64_t nwid, const char* domain, const std::vector<InetAddress>& servers)
{
    try {
        if (dnsConfiguredForNwid[nwid]) {
            logToFile("DNS settings for nwid " + nwidToHex(nwid) + " are already applied, skipping reconfiguration.");
            return;
        }

        std::ostringstream dnsLog;
        dnsLog << "DNS servers received for nwid " << nwid << ": ";
        for (const auto& server : servers) {
            char ipaddr[256] = { 0 };
            server.toIpString(ipaddr);
            dnsLog << ipaddr << " ";
        }
        dnsLog << "| DNS Suffix: " << domain;
        logToFile(dnsLog.str());

        std::string interfaceName = getTapAdapterName(nwid);

        std::ostringstream ss;
        for (auto it = servers.begin(); it != servers.end(); ++it) {
            char ipaddr[256] = { 0 };
            it->toIpString(ipaddr);
            ss << ipaddr;
            if ((it + 1) != servers.end()) {
                ss << " ";
            }
        }
        std::string serverValue = ss.str();
        logToFile("Generated DNS server string: " + serverValue);

        // Configure static DNS
        std::ostringstream command;
        command << "netsh interface ip set dns \"" << interfaceName << "\" static " << serverValue;
        logToFile("Executing command to set DNS: " + command.str());
        int retCode = system(command.str().c_str());
        if (retCode != 0) {
            logToFile("Failed to set DNS on interface " + interfaceName + ": return code " + std::to_string(retCode));
        } else {
            logToFile("DNS set successfully on interface " + interfaceName + " with servers: " + serverValue);
        }

        // Set DNS suffix using PowerShell
        std::ostringstream psCommand;
        psCommand << "Get-NetAdapter | Where-Object { $_.Name -eq '" << interfaceName
                  << "' } | ForEach-Object { Set-DnsClient -InterfaceIndex $_.IfIndex -ConnectionSpecificSuffix '"
                  << domain << "'; ipconfig /registerdns }";
        executePowerShellCommand(psCommand.str());

        // Mark DNS as configured
        dnsConfiguredForNwid[nwid] = true;
    } catch (const std::exception& e) {
        logToFile("Error in setDNS: " + std::string(e.what()));
    }
}

/**
 * Removes the DNS configuration for the given nwid.
 * - Resets the adapter to use DHCP for DNS.
 * - Clears the configuration status for the nwid.
 */
void WinDNSHelper::removeDNS(uint64_t nwid)
{
    try {
        std::string interfaceName = getTapAdapterName(nwid);

        std::ostringstream command;
        command << "netsh interface ip set dns \"" << interfaceName << "\" dhcp";
        logToFile("Executing command: " + command.str());

        int retCode = system(command.str().c_str());
        if (retCode != 0) {
            logToFile("Failed to remove DNS on interface " + interfaceName + ": return code " + std::to_string(retCode));
        } else {
            logToFile("DNS removed successfully on interface " + interfaceName);
        }

        // Clear the DNS configuration status
        dnsConfiguredForNwid.erase(nwid);
    } catch (const std::exception& e) {
        logToFile("Error in removeDNS: " + std::string(e.what()));
    }
}

} // namespace ZeroTier
