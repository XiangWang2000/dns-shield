package io.github.xiangwang2000.dnsshield.data

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface DnsDao {
    // Bypassed Apps
    @Query("SELECT * FROM bypassed_apps ORDER BY appName COLLATE NOCASE ASC")
    fun getBypassedAppsFlow(): Flow<List<BypassedApp>>

    @Query("SELECT * FROM bypassed_apps ORDER BY appName COLLATE NOCASE ASC")
    suspend fun getBypassedAppsList(): List<BypassedApp>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertBypassedApp(app: BypassedApp)

    @Query("DELETE FROM bypassed_apps WHERE packageName = :packageName")
    suspend fun deleteBypassedAppByPackage(packageName: String)

    // DNS Servers
    @Query("SELECT * FROM dns_servers ORDER BY isCustom ASC, id ASC")
    fun getDnsServersFlow(): Flow<List<DnsServer>>

    @Query("SELECT * FROM dns_servers ORDER BY isCustom ASC, id ASC")
    suspend fun getDnsServersList(): List<DnsServer>

    @Query("SELECT * FROM dns_servers WHERE isActive = 1 LIMIT 1")
    suspend fun getActiveDnsServer(): DnsServer?

    @Query("SELECT * FROM dns_servers WHERE isActive = 1 LIMIT 1")
    fun getActiveDnsServerFlow(): Flow<DnsServer?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertDnsServer(server: DnsServer)

    @Query("SELECT * FROM dns_servers WHERE id = :serverId LIMIT 1")
    suspend fun getDnsServerById(serverId: Int): DnsServer?

    @Query("DELETE FROM dns_servers WHERE id = :serverId")
    suspend fun deleteDnsServerById(serverId: Int): Int

    @Query("UPDATE dns_servers SET isActive = 1 WHERE id = :serverId")
    suspend fun activateDnsById(serverId: Int): Int

    @Query("UPDATE dns_servers SET isActive = 0 WHERE id != :serverId")
    suspend fun deactivateOtherDns(serverId: Int): Int

    @Transaction
    suspend fun setActiveDnsServer(serverId: Int): Boolean {
        val affectedRows = activateDnsById(serverId)
        if (affectedRows == 0) {
            return false
        }
        deactivateOtherDns(serverId)
        return true
    }

    @Transaction
    suspend fun deleteDnsServerSafely(serverId: Int): Boolean {
        val allServers = getDnsServersList()

        // 避免刪掉最後一個 DNS
        if (allServers.size <= 1) {
            return false
        }

        val target = getDnsServerById(serverId) ?: return false

        if (target.isActive) {
            val fallback = allServers.firstOrNull { it.id != serverId }
                ?: return false

            // 先切換 active DNS，成功後才刪除舊的
            val switched = setActiveDnsServer(fallback.id)
            if (!switched) {
                return false
            }
        }

        return deleteDnsServerById(serverId) > 0
    }
}
