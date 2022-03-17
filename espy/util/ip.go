package util

import "net"

//SelectPublicPrivateIPs selects properly formatted public and private IP addresses
//from the given string slice
func SelectPublicPrivateIPs(ips []string) []string {
	outIPs := make([]string, 0, len(ips))
	for i := range ips {
		ip := net.ParseIP(ips[i])
		if ip == nil {
			continue
		}

		// cache IPv4 conversion so it not performed every in every ip.IsXXX method
		if ipv4 := ip.To4(); ipv4 != nil {
			ip = ipv4
		}

		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}

		outIPs = append(outIPs, ips[i])
	}
	return outIPs
}
