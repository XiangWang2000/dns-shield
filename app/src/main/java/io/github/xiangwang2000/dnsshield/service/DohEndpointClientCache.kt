package io.github.xiangwang2000.dnsshield.service

import okhttp3.OkHttpClient

/**
 * Keep endpoint DNS identity stable for pooling. Only the current resolver configuration is retained.
 * A new immutable base client (including TLS settings/network generation) retires the old clients.
 * Existing in-flight calls keep their original client and remain subject to the service's stale fence.
 */
internal class DohEndpointClientCache {
    private var baseClient: OkHttpClient? = null
    private var configuration: List<DnsDohEndpoint> = emptyList()
    private var clients: Map<DnsDohEndpoint, OkHttpClient> = emptyMap()

    @Synchronized
    fun clientFor(
        base: OkHttpClient,
        endpoints: List<DnsDohEndpoint>,
        endpoint: DnsDohEndpoint
    ): OkHttpClient {
        require(endpoint in endpoints)
        if (baseClient !== base || configuration != endpoints) {
            val nextConfiguration = endpoints.toList()
            val nextClients = nextConfiguration.associateWith { base.forDohEndpoint(it) }
            baseClient = base
            configuration = nextConfiguration
            clients = nextClients
        }
        return clients.getValue(endpoint)
    }
}