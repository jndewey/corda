package net.corda.node.services.config

import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.Test
import java.nio.file.Paths

class FullNodeConfigurationTest {
    @Test
    fun `Artemis special characters not permitted in RPC usernames`() {
        fun configWithRPCUsername(username: String): FullNodeConfiguration {
            return FullNodeConfiguration(ConfigHelper.loadConfig(
                    baseDirectoryPath = Paths.get("."),
                    allowMissingConfig = true,
                    configOverrides = mapOf(
                            "rpcUsers" to listOf(
                                    mapOf(
                                            "username" to username,
                                            "password" to "password"
                                    )
                            )
                    )
            ))
        }

        assertThatThrownBy { configWithRPCUsername("user.1") }.hasMessageContaining(".")
        assertThatThrownBy { configWithRPCUsername("user*1") }.hasMessageContaining("*")
        assertThatThrownBy { configWithRPCUsername("user#1") }.hasMessageContaining("#")
    }
}
