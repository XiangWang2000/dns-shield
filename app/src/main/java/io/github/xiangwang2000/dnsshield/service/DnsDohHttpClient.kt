package io.github.xiangwang2000.dnsshield.service

import okhttp3.OkHttpClient

/** Keep DoH requests on the explicitly configured endpoint, including across redirects. */
internal fun OkHttpClient.forDohEndpoints(endpoints: List<DnsDohEndpoint>): OkHttpClient =
    newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .dns(DohBootstrapDns.forEndpoints(endpoints))
        .build()
