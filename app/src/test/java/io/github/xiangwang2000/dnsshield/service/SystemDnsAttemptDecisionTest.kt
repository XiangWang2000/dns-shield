package io.github.xiangwang2000.dnsshield.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SystemDnsAttemptDecisionTest {
    @Test
    fun validAnswerIsReturnedWithoutConsultingTheRetryPath() {
        val answer = byteArrayOf(1, 2, 3)

        val action = decideFirstSystemDnsAttempt(
            outcome = SystemDnsAttemptOutcome.Answer(answer),
            systemErrorCode = 3,
            isValid = { true }
        )

        assertEquals(SystemDnsFirstAttemptAction.RETURN_ANSWER, action)
    }

    @Test
    fun invalidAnswerRequestsAnEdnsRetry() {
        var validated = false

        val action = decideFirstSystemDnsAttempt(
            outcome = SystemDnsAttemptOutcome.Answer(byteArrayOf(1, 2, 3)),
            systemErrorCode = 3,
            isValid = {
                validated = true
                false
            }
        )

        assertTrue(validated)
        assertEquals(SystemDnsFirstAttemptAction.RETRY_WITH_EDNS, action)
    }

    @Test
    fun systemWideResolverErrorRequestsAnEdnsRetry() {
        var validated = false

        val action = decideFirstSystemDnsAttempt(
            outcome = SystemDnsAttemptOutcome.Error(code = 3),
            systemErrorCode = 3,
            isValid = {
                validated = true
                true
            }
        )

        assertFalse(validated)
        assertEquals(SystemDnsFirstAttemptAction.RETRY_WITH_EDNS, action)
    }

    @Test
    fun otherResolverErrorsAreFinal() {
        val action = decideFirstSystemDnsAttempt(
            outcome = SystemDnsAttemptOutcome.Error(code = 0),
            systemErrorCode = 3,
            isValid = { true }
        )

        assertEquals(SystemDnsFirstAttemptAction.GIVE_UP, action)
    }

    @Test
    fun unavailableAttemptWithoutRemainingDeadlineGivesUp() {
        var validated = false

        val action = decideFirstSystemDnsAttempt(
            outcome = SystemDnsAttemptOutcome.Unavailable,
            systemErrorCode = 3,
            isValid = {
                validated = true
                true
            }
        )

        assertFalse(validated)
        assertEquals(SystemDnsFirstAttemptAction.GIVE_UP, action)
    }
}
