package io.github.xiangwang2000.dnsshield.viewmodel

import io.github.xiangwang2000.dnsshield.data.DnsServer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import java.util.concurrent.atomic.AtomicBoolean

internal sealed interface ResolverCommandResult<out T> {
    data class Completed<T>(val value: T) : ResolverCommandResult<T>
    data class Failed(val cause: Exception, val persisted: Boolean) : ResolverCommandResult<Nothing>
}

internal enum class ResolverCommandApplyStatus {
    NOT_SAVED,
    SAVED_UNSYNCED,
    APPLIED
}

internal object ResolverCommandFailureMessages {
    const val SELECT_NOT_SAVED =
        "DNS 切換失敗，設定沒有儲存。請稍後重試。"
    const val SELECT_SAVED_UNSYNCED =
        "DNS 切換已儲存，但這次未同步至防護服務；請重新選取目前的 DNS 以套用設定。"
    const val FALLBACK_ALLOW_NOT_SAVED =
        "DNS 傳輸政策沒有儲存；本次未啟用明文備援。請再次設定明文備援。"
    const val FALLBACK_STRICT_NOT_SAVED =
        "DNS 傳輸政策沒有儲存；明文備援已維持關閉。請再次設定僅加密模式。"
    const val FALLBACK_ALLOW_SAVED_UNSYNCED =
        "DNS 傳輸政策已儲存，但防護服務尚未同步；請關閉後再開啟明文備援。"
    const val FALLBACK_STRICT_SAVED_UNSYNCED =
        "僅加密政策已儲存，但這次未同步至防護服務；請重新選取目前的 DNS 以套用設定。"
    const val FALLBACK_SAVED_UNSYNCED =
        "DNS 傳輸設定已儲存，這次未同步至防護服務；請確認最新設定。"
    const val DELETE_NOT_SAVED =
        "刪除 DNS 設定沒有完成，資料沒有變更。請稍後重試。"
    const val DELETE_SAVED_UNSYNCED =
        "DNS 設定已刪除，但這次未同步至防護服務；請重新選取目前的 DNS 以套用設定。"
}
internal data class ResolverCommandOperations(
    val setActiveDnsServer: suspend (Int) -> Boolean,
    val getActiveDnsServer: suspend () -> DnsServer?,
    val updatePlaintextFallback: suspend (Int, Boolean) -> Int,
    val deleteDnsServerSafely: suspend (Int) -> Boolean,
    val dispatch: (DnsServer, Long) -> Unit
)

internal suspend fun <T> awaitResolverCommandResult(
    result: Deferred<T>,
    persisted: AtomicBoolean
): ResolverCommandResult<T> {
    return try {
        ResolverCommandResult.Completed(result.await())
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (exception: Exception) {
        ResolverCommandResult.Failed(exception, persisted.get())
    }
}

internal suspend fun persistFallbackPolicy(
    allow: Boolean,
    applyRuntimePolicy: (Boolean) -> Boolean,
    onPersisted: () -> Unit,
    persist: suspend () -> Boolean,
    dispatch: suspend () -> Boolean
): ResolverCommandApplyStatus {
    val strictFenceApplied = allow || applyRuntimePolicy(false)

    if (!persist()) return ResolverCommandApplyStatus.NOT_SAVED
    onPersisted()

    if (!dispatch()) return ResolverCommandApplyStatus.SAVED_UNSYNCED
    if (allow && !applyRuntimePolicy(true)) return ResolverCommandApplyStatus.SAVED_UNSYNCED

    return if (strictFenceApplied) {
        ResolverCommandApplyStatus.APPLIED
    } else {
        ResolverCommandApplyStatus.SAVED_UNSYNCED
    }
}
