package io.github.xiangwang2000.dnsshield.blocking

import android.content.res.AssetManager

/** Describes the one-shot production Public Suffix load owned by a runtime lifecycle. */
sealed class PublicSuffixResolverStatus {
    data object NotLoaded : PublicSuffixResolverStatus()

    data class Loaded(
        val exactRules: Int,
        val wildcardRules: Int,
        val exceptionRules: Int
    ) : PublicSuffixResolverStatus()

    data class Rejected(val reason: String) : PublicSuffixResolverStatus() {
        init {
            require(reason.isNotBlank()) { "Public Suffix rejection reason must not be blank" }
        }
    }
}

/**
 * Owns at most one production Public Suffix resolver for one service or policy lifecycle.
 *
 * A successful load is reused by every later and concurrent caller. A failed load is also terminal
 * for this owner instance because an APK asset cannot repair itself during the same process
 * lifecycle; caching that failure prevents repeated asset I/O, hashing, and parsing on hot paths.
 *
 * This owner is deliberately not wired into DNS blocking yet.
 */
class PublicSuffixResolverOwner internal constructor(
    private val loadResolver: () -> CompiledPublicSuffixList
) {
    @Volatile
    private var state: State = State.NotLoaded

    fun resolverOrNull(): CompiledPublicSuffixList? {
        when (val current = state) {
            is State.Loaded -> return current.resolver
            is State.Rejected -> return null
            State.NotLoaded -> Unit
        }

        return synchronized(this) {
            when (val current = state) {
                is State.Loaded -> current.resolver
                is State.Rejected -> null
                State.NotLoaded -> {
                    state = try {
                        State.Loaded(loadResolver())
                    } catch (exception: Exception) {
                        State.Rejected(
                            exception.message?.takeIf(String::isNotBlank)
                                ?: exception.javaClass.simpleName
                        )
                    }
                    (state as? State.Loaded)?.resolver
                }
            }
        }
    }

    fun status(): PublicSuffixResolverStatus = when (val current = state) {
        State.NotLoaded -> PublicSuffixResolverStatus.NotLoaded
        is State.Loaded -> PublicSuffixResolverStatus.Loaded(
            exactRules = current.resolver.exactRuleCount,
            wildcardRules = current.resolver.wildcardRuleCount,
            exceptionRules = current.resolver.exceptionRuleCount
        )
        is State.Rejected -> PublicSuffixResolverStatus.Rejected(current.reason)
    }

    private sealed class State {
        data object NotLoaded : State()
        data class Loaded(val resolver: CompiledPublicSuffixList) : State()
        data class Rejected(val reason: String) : State()
    }

    companion object {
        fun fromAssets(
            assets: AssetManager,
            assetName: String = PublicSuffixAssetLoader.ASSET_NAME
        ): PublicSuffixResolverOwner {
            val loader = PublicSuffixAssetLoader.fromAssets(assets, assetName)
            return PublicSuffixResolverOwner(loader::load)
        }
    }
}
