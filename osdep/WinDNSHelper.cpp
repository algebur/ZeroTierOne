#include "WinDNSHelper.hpp"

#include <IPHlpApi.h>
#include <string>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <cstdlib>

#pragma comment(lib, "IPHlpApi.lib")

namespace ZeroTier {

// Convert uint64_t to hex string
std::string nwidToHex(uint64_t nwid)
{
    std::ostringstream ss;
    ss << std::hex << nwid;
    return ss.str();
}

// Helper function to get the name of the TAP adapter based on nwid
std::string getTapAdapterName(uint64_t nwid)
{
    ULONG outBufLen = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;

    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddresses, &outBufLen) != ERROR_BUFFER_OVERFLOW) {
        throw std::runtime_error("Failed to retrieve buffer size for adapter addresses");
    }

    pAddresses = static_cast<PIP_ADAPTER_ADDRESSES>(malloc(outBufLen));
    if (!pAddresses) {
        throw std::runtime_error("Memory allocation failed for adapter addresses");
    }

    std::string hexNwid = nwidToHex(nwid);

    try {
        for (int i = 0; i < 5; ++i) {
            if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddresses, &outBufLen) == NO_ERROR) {
                for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != nullptr; pCurrAddresses = pCurrAddresses->Next) {
                    std::wstring ws(pCurrAddresses->FriendlyName);
                    std::string friendlyName(ws.begin(), ws.end());

                    if (friendlyName.find(hexNwid) != std::string::npos) {
                        free(pAddresses);
                        return friendlyName;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch (...) {
        free(pAddresses);
        throw;
    }

    free(pAddresses);
    throw std::runtime_error("Unable to find TAP adapter for nwid " + hexNwid);
}

// Helper function to execute PowerShell commands
bool executePowerShellCommand(const std::string& command)
{
    std::ostringstream psCommand;
    psCommand << "powershell.exe -Command \"" << command << "\"";

    FILE* pipe = _popen(psCommand.str().c_str(), "r");
    if (!pipe) {
        return false;
    }

    char buffer[128];
    std::string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    int retCode = _pclose(pipe);

    return retCode == 0;
}

void WinDNSHelper::setDNS(uint64_t nwid, const char* domain, const std::vector<InetAddress>& servers)
{
    try {
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

        std::ostringstream command;
        command << "netsh interface ip set dns \"" << interfaceName << "\" static " << serverValue;
        system(command.str().c_str());

        // Set DNS suffix using PowerShell
        std::ostringstream psCommand;
        psCommand << "Get-NetAdapter | Where-Object { $_.Name -eq '" << interfaceName
                  << "' } | ForEach-Object { Set-DnsClient -InterfaceIndex $_.IfIndex -ConnectionSpecificSuffix '"
                  << domain << "'; ipconfig /registerdns }";
        executePowerShellCommand(psCommand.str());
    } catch (const std::exception&) {
        // Handle exception silently
    }
}

void WinDNSHelper::removeDNS(uint64_t nwid)
{
    try {
        std::string interfaceName = getTapAdapterName(nwid);

        std::ostringstream command;
        command << "netsh interface ip set dns \"" << interfaceName << "\" dhcp";
        system(command.str().c_str());
    } catch (const std::exception&) {
        // Handle exception silently
    }
}

} // namespace ZeroTier
