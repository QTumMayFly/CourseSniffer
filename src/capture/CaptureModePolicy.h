#pragma once

#include <pcap/pcap.h>

namespace sniffer {

enum class CaptureSetupAction { Continue, RetryOrdinary, Fail };

constexpr bool requestsPromiscuousMode(unsigned int interfaceFlags) {
    return (interfaceFlags & PCAP_IF_LOOPBACK) == 0;
}

constexpr CaptureSetupAction captureSetupAction(bool promiscuousRequested, int status) {
    if (promiscuousRequested &&
        (status == PCAP_WARNING_PROMISC_NOTSUP || status == PCAP_ERROR_PROMISC_PERM_DENIED))
        return CaptureSetupAction::RetryOrdinary;
    return status < 0 ? CaptureSetupAction::Fail : CaptureSetupAction::Continue;
}

}
