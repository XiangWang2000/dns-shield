package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsMessageValidatorTest {
    @Test
    fun parsesAaaaAndEdnsQueriesWithoutTreatingMalformedNamesAsDomains() {
        val aResult = DnsMessageValidator.parseQuery(DnsTestMessages.query(name = "Ads.Example", type = 1))
        val aaaaResult = DnsMessageValidator.parseQuery(DnsTestMessages.query(name = "ads.example", type = 28))
        val ednsResult = DnsMessageValidator.parseQuery(DnsTestMessages.query(edns = true))

        val a = assertIs<DnsQueryParseResult.Valid>(aResult).query
        val aaaa = assertIs<DnsQueryParseResult.Valid>(aaaaResult).query
        val edns = assertIs<DnsQueryParseResult.Valid>(ednsResult).query
        assertEquals("ads.example", a.question.domainName)
        assertEquals(1, a.question.type)
        assertEquals(28, aaaa.question.type)
        assertEquals("example.com", edns.question.domainName)
        assertEquals(DnsTestMessages.queryQuestionEnd(edns.wire), edns.questionEndOffset)

        val binaryLabel = DnsTestMessages.query(name = "binary.example").also { it[13] = 0xFF.toByte() }
        val parsedBinaryLabel = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(binaryLabel)).query
        assertNull(parsedBinaryLabel.question.domainName)
    }

    @Test
    fun capsForwardedEdnsUdpPayloadToTheSupportedResponseSize() {
        val oversizedEdnsQuery = DnsTestMessages.query(edns = true, udpPayloadSize = 65_535)
        val parsed = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(oversizedEdnsQuery)).query
        val upstreamQuery = DnsMessageValidator.prepareUpstreamQuery(parsed)
        val upstreamParsed = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(upstreamQuery)).query

        assertEquals(65_535, readUnsignedShort(oversizedEdnsQuery, DnsTestMessages.queryQuestionEnd(oversizedEdnsQuery) + 3))
        assertEquals(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES, parsed.maxUdpResponseBytes)
        assertEquals(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES, upstreamParsed.maxUdpResponseBytes)
        assertEquals(DnsMessageValidator.MAX_DNS_MESSAGE_BYTES, readUnsignedShort(upstreamQuery, DnsTestMessages.queryQuestionEnd(upstreamQuery) + 3))

        val undersizedEdnsQuery = DnsTestMessages.query(edns = true, udpPayloadSize = 256)
        val undersizedParsed = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(undersizedEdnsQuery)).query
        val minimumSizeQuery = DnsMessageValidator.prepareUpstreamQuery(undersizedParsed)
        assertEquals(512, undersizedParsed.maxUdpResponseBytes)
        assertEquals(512, readUnsignedShort(minimumSizeQuery, DnsTestMessages.queryQuestionEnd(minimumSizeQuery) + 3))
    }

    @Test
    fun rejectsTruncatedHeadersUnsupportedOpcodesAndQuestionCounts() {
        assertIs<DnsQueryParseResult.Rejected>(DnsMessageValidator.parseQuery(ByteArray(11)))

        val response = DnsTestMessages.response(DnsTestMessages.query())
        assertEquals(
            RejectionReason.RESPONSE_PACKET,
            assertIs<DnsQueryParseResult.Rejected>(DnsMessageValidator.parseQuery(response)).reason
        )

        val unsupportedOpcode = DnsTestMessages.query().also { it[2] = 0x09 }
        assertEquals(
            RejectionReason.UNSUPPORTED_OPCODE,
            assertIs<DnsQueryParseResult.Rejected>(DnsMessageValidator.parseQuery(unsupportedOpcode)).reason
        )

        val wrongQuestionCount = DnsTestMessages.query().also { it[5] = 2 }
        assertEquals(
            RejectionReason.QUESTION_COUNT,
            assertIs<DnsQueryParseResult.Rejected>(DnsMessageValidator.parseQuery(wrongQuestionCount)).reason
        )

        val truncatedLabel = DnsTestMessages.query().also { it[12] = 63 }
        assertIs<DnsQueryParseResult.Rejected>(DnsMessageValidator.parseQuery(truncatedLabel))

        val duplicateOptQuery = DnsTestMessages.duplicateAdditionalOpt(DnsTestMessages.query(edns = true))
        assertEquals(
            RejectionReason.INVALID_SECTION,
            assertIs<DnsQueryParseResult.Rejected>(DnsMessageValidator.parseQuery(duplicateOptQuery)).reason
        )
    }

    @Test
    fun acceptsBackwardCompressedRecordNamesAndRejectsCompressionLoops() {
        val query = DnsTestMessages.query()
        val compressedRecord = query.copyOf(query.size + 12).also { message ->
            message[10] = 0
            message[11] = 1
            val offset = query.size
            message[offset] = 0xC0.toByte()
            message[offset + 1] = 12
            message[offset + 2] = 0xFD.toByte()
            message[offset + 3] = 0xE8.toByte()
            message[offset + 4] = 0
            message[offset + 5] = 1
        }
        assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(compressedRecord))

        val pointerLoop = query.copyOf(query.size + 12).also { message ->
            message[10] = 0
            message[11] = 1
            val offset = query.size
            message[offset] = 0xC0.toByte()
            message[offset + 1] = offset.toByte()
            message[offset + 2] = 0xFD.toByte()
            message[offset + 3] = 0xE8.toByte()
            message[offset + 4] = 0
            message[offset + 5] = 1
        }
        assertIs<DnsQueryParseResult.Rejected>(DnsMessageValidator.parseQuery(pointerLoop))
    }

    @Test
    fun validatesResponseIdFlagsAndQuestionBeforeAccepting() {
        val queryBytes = DnsTestMessages.query(name = "Ads.Example", type = 28)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val valid = DnsTestMessages.response(queryBytes, name = "ads.example")
        assertTrue(DnsMessageValidator.isValidResponse(valid, query))

        val wrongId = valid.copyOf().also { it[1] = (it[1].toInt() xor 1).toByte() }
        val notAResponse = valid.copyOf().also { it[2] = (it[2].toInt() and 0x7F).toByte() }
        val wrongType = valid.copyOf().also { it[it.size - 3] = (it[it.size - 3].toInt() xor 1).toByte() }
        val wrongQuestion = DnsTestMessages.response(queryBytes, name = "other.example")
        val malformedTail = valid + byteArrayOf(1)

        assertFalse(DnsMessageValidator.isValidResponse(wrongId, query))
        assertFalse(DnsMessageValidator.isValidResponse(notAResponse, query))
        assertFalse(DnsMessageValidator.isValidResponse(wrongType, query))
        assertFalse(DnsMessageValidator.isValidResponse(wrongQuestion, query))
        assertFalse(DnsMessageValidator.isValidResponse(malformedTail, query))
    }

    @Test
    fun rejectsMalformedKnownRecordDataAndDoesNotCacheServFailOrTruncatedResponses() {
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val malformedAResponse = DnsTestMessages.responseWithAnswer(queryBytes, type = 1, data = byteArrayOf(192.toByte()))
        val aaaaQueryBytes = DnsTestMessages.query(type = 28)
        val aaaaQuery = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(aaaaQueryBytes)).query
        val malformedAaaaResponse = DnsTestMessages.responseWithAnswer(aaaaQueryBytes, type = 28, data = ByteArray(15))
        assertFalse(DnsMessageValidator.isValidResponse(malformedAResponse, query))
        assertFalse(DnsMessageValidator.isValidResponse(malformedAaaaResponse, aaaaQuery))

        val servFail = DnsMessageValidator.buildServFailResponse(query)
        val truncated = DnsTestMessages.response(queryBytes, flags = 0x8380)
        val noError = DnsTestMessages.response(queryBytes)
        val nxDomain = DnsMessageValidator.buildNxDomainResponse(query)
        assertTrue(DnsMessageValidator.isValidResponse(servFail, query))
        assertTrue(DnsMessageValidator.isValidResponse(truncated, query))
        assertFalse(DnsMessageValidator.isCacheableResponse(servFail, query))
        assertFalse(DnsMessageValidator.isCacheableResponse(truncated, query))
        assertTrue(DnsMessageValidator.isCacheableResponse(noError, query))
        assertTrue(DnsMessageValidator.isCacheableResponse(nxDomain, query))
    }

    @Test
    fun validatesAfsdbKeyAndPxRecordLayouts() {
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val hostname = DnsTestMessages.encodedName("server.example")
        val mappingNames = DnsTestMessages.encodedName("mail.example") +
            DnsTestMessages.encodedName("x400.example")

        val afsdb = DnsTestMessages.responseWithAnswer(
            queryBytes,
            type = 18,
            data = byteArrayOf(0, 1) + hostname
        )
        val key = DnsTestMessages.responseWithAnswer(
            queryBytes,
            type = 25,
            data = byteArrayOf(0, 1, 3, 8, 0x7F)
        )
        val px = DnsTestMessages.responseWithAnswer(
            queryBytes,
            type = 26,
            data = byteArrayOf(0, 50) + mappingNames
        )

        assertTrue(DnsMessageValidator.isValidResponse(afsdb, query))
        assertTrue(DnsMessageValidator.isValidResponse(key, query))
        assertTrue(DnsMessageValidator.isValidResponse(px, query))
        assertFalse(
            DnsMessageValidator.isValidResponse(
                DnsTestMessages.responseWithAnswer(queryBytes, type = 18, data = byteArrayOf(0, 1)),
                query
            )
        )
        assertFalse(
            DnsMessageValidator.isValidResponse(
                DnsTestMessages.responseWithAnswer(queryBytes, type = 25, data = byteArrayOf(0, 1, 3)),
                query
            )
        )
    }

    @Test
    fun doesNotCacheResponsesWithEdnsExtendedErrorCodes() {
        val queryBytes = DnsTestMessages.query(edns = true)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val noError = DnsTestMessages.responseWithOpt(queryBytes, extendedRcode = 0)
        val badVersion = DnsTestMessages.responseWithOpt(queryBytes, extendedRcode = 1)
        val misplacedOpt = DnsTestMessages.responseWithOpt(queryBytes, extendedRcode = 0, section = 0)
        val duplicateOpt = DnsTestMessages.responseWithOpt(queryBytes, extendedRcode = 0, copies = 2)

        assertTrue(DnsMessageValidator.isValidResponse(badVersion, query))
        assertFalse(DnsMessageValidator.isCacheableResponse(noError, query))
        assertFalse(DnsMessageValidator.isCacheableResponse(badVersion, query))
        assertFalse(DnsMessageValidator.isValidResponse(misplacedOpt, query))
        assertFalse(DnsMessageValidator.isValidResponse(duplicateOpt, query))
    }

    @Test
    fun rejectsOptResponseToQueryThatDidNotOfferEdns() {
        val queryBytes = DnsTestMessages.query()
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        val unsolicitedOpt = DnsTestMessages.responseWithOpt(queryBytes, extendedRcode = 0)

        assertFalse(DnsMessageValidator.isValidResponse(unsolicitedOpt, query))
    }

    @Test
    fun syntheticNxDomainAndServFailHaveConsistentCountsAndDropUncopiedEdnsData() {
        val queryBytes = DnsTestMessages.query(edns = true)
        val query = assertIs<DnsQueryParseResult.Valid>(DnsMessageValidator.parseQuery(queryBytes)).query
        listOf(
            DnsMessageValidator.buildNxDomainResponse(query) to 3,
            DnsMessageValidator.buildServFailResponse(query) to 2
        ).forEach { (response, expectedRcode) ->
            assertEquals(query.questionEndOffset, response.size)
            assertEquals(1, readUnsignedShort(response, 4))
            assertEquals(0, readUnsignedShort(response, 6))
            assertEquals(0, readUnsignedShort(response, 8))
            assertEquals(0, readUnsignedShort(response, 10))
            assertEquals(expectedRcode, response[3].toInt() and 0x0F)
            assertTrue(DnsMessageValidator.isValidResponse(response, query))
            val independentlyParsed = DnsTestMessages.parseSimpleResponseIndependently(response)
            assertEquals(expectedRcode, independentlyParsed?.rcode)
            assertEquals("example.com", independentlyParsed?.name)
            assertEquals(0, independentlyParsed?.answerCount)
            assertEquals(0, independentlyParsed?.authorityCount)
            assertEquals(0, independentlyParsed?.additionalCount)
            assertContentEquals(
                queryBytes.copyOfRange(12, query.questionEndOffset),
                response.copyOfRange(12, query.questionEndOffset)
            )
        }
    }
}
