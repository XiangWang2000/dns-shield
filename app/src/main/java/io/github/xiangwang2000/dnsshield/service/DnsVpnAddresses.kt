package io.github.xiangwang2000.dnsshield.service

/** Local-only DNS endpoints; only these host routes are captured by the VPN. */
internal object DnsVpnAddresses {
    const val IPV4_CLIENT = "10.0.0.2"
    const val IPV4_DNS = "10.0.0.1"
    const val IPV6_CLIENT = "fd29:1a5d:7c0d::2"
    const val IPV6_DNS = "fd29:1a5d:7c0d::1"
    private val ipv6Endpoints by lazy {
        listOf(IPV6_DNS, IPV6_CLIENT).map { requireNotNull(IpAddressLiteral.parse(it)).toInetAddress().address }
    }

    fun overlapsIpv6Prefix(address: ByteArray, prefixLength: Int): Boolean {
        require(address.size == 16 && prefixLength in 0..128)
        val wholeBytes = prefixLength / 8
        val remainingBits = prefixLength % 8
        return ipv6Endpoints.any { endpoint ->
            (0 until wholeBytes).all { endpoint[it] == address[it] } &&
                (remainingBits == 0 ||
                    ((endpoint[wholeBytes].toInt() xor address[wholeBytes].toInt()) and
                        (0xFF shl (8 - remainingBits))) == 0)
        }
    }
}
