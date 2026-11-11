package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DnsVpnAddressesTest {
    @Test
    fun detectsOnlyPrefixesContainingAVirtualEndpoint() {
        fun overlaps(address: String, prefix: Int) = DnsVpnAddresses.overlapsIpv6Prefix(
            requireNotNull(IpAddressLiteral.parse(address)).toInetAddress().address, prefix
        )
        assertTrue(overlaps("fd29:1a5d:7c0d::abcd", 64))
        assertTrue(overlaps(DnsVpnAddresses.IPV6_DNS, 128))
        assertTrue(overlaps(DnsVpnAddresses.IPV6_CLIENT, 128))
        assertFalse(overlaps("fd29:1a5d:7c0d::3", 128))
        assertTrue(overlaps("fd29:1a5d:7c0d::3", 127))
        assertFalse(overlaps("fd29:1a5d:7c0d::4", 126))
        assertTrue(overlaps("fd29:1a5d:7c0d::4", 125))
        assertFalse(overlaps("fd29:1a5d:7c0e::1", 64))
        assertFalse(overlaps("2001:db8::1", 32))
        assertTrue(overlaps("2001:db8::1", 0))
    }
}
