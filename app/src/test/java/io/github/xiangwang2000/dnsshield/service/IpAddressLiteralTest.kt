package io.github.xiangwang2000.dnsshield.service

import java.net.Inet6Address
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IpAddressLiteralTest {
    @Test
    fun parsesAndNormalizesIpv4AndCompressedIpv6() {
        assertTrue(isIpv4Literal("192.0.2.1"))
        assertFalse(isIpv4Literal("256.0.2.1"))
        assertEquals("192.0.2.1", IpAddressLiteral.parse("192.000.002.001")?.normalized)

        val parsed = assertNotNull(IpAddressLiteral.parse("2001:0DB8:0:0:0:0:0:1"))
        assertEquals("2001:db8::1", parsed.normalized)
        assertTrue(isIpLiteral("2001:db8::1"))
    }

    @Test
    fun mappedIpv6FormsNormalizeToOneLiteralAndRoundTripAsIpv6() {
        val dotted = assertNotNull(IpAddressLiteral.parse("::ffff:192.0.2.1"))
        val hexadecimal = assertNotNull(IpAddressLiteral.parse("0:0:0:0:0:ffff:c000:201"))

        assertEquals("::ffff:c000:201", dotted.normalized)
        assertEquals(dotted.normalized, hexadecimal.normalized)
        val address = dotted.toInetAddress()
        assertTrue(address is Inet6Address)
        assertEquals(dotted.normalized, IpAddressLiteral.parse(requireNotNull(address.hostAddress))?.normalized)
    }

    @Test
    fun rejectsHostnamesUrlSyntaxScopesAndMalformedIpv6() {
        listOf(
            "resolver.example",
            "https://192.0.2.1",
            "[2001:db8::1]",
            "fe80::1%wlan0",
            "2001::db8::1",
            "2001:db8::gg",
            "1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:8:9",
            "::ffff:192.0.2.256"
        ).forEach { value ->
            assertNull(IpAddressLiteral.parse(value), value)
            assertFalse(isIpLiteral(value), value)
        }
    }
}
