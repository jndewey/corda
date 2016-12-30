package net.corda.node.services.config

import com.google.common.net.HostAndPort
import com.typesafe.config.Config
import com.typesafe.config.ConfigRenderOptions.defaults
import com.typesafe.config.ConfigValueFactory
import net.corda.core.div
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import java.net.URL
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.time.LocalDate
import java.util.*

class ConfigUtilitiesTest {
    @Test
    fun `String`() {
        class StringTest(config: Config) {
            val value: String by config
        }
        assertThat(StringTest(config("value" to "this is the string!")).value).isEqualTo("this is the string!")
    }

    @Test
    fun `List of String`() {
        class ListTest(config: Config) {
            val value: List<String> by config
        }
        assertThat(ListTest(config("value" to listOf("a", "b"))).value).isEqualTo(listOf("a", "b"))
    }

    @Test
    fun `Int`() {
        class IntTest(config: Config) {
            val value: Int by config
        }
        assertThat(IntTest(config("value" to 987654321)).value).isEqualTo(987654321)
    }

    @Test
    fun `List of Int`() {
        class ListTest(config: Config) {
            val value: List<Int> by config
        }
        assertThat(ListTest(config("value" to listOf(123))).value).isEqualTo(listOf(123))
    }

    @Test
    fun `Long`() {
        class LongTest(config: Config) {
            val value: Long by config
        }
        assertThat(LongTest(config("value" to Long.MAX_VALUE)).value).isEqualTo(Long.MAX_VALUE)
    }

    @Test
    fun `List of Long`() {
        class ListTest(config: Config) {
            val value: List<Long> by config
        }
        assertThat(ListTest(config("value" to listOf(Long.MAX_VALUE, Long.MIN_VALUE))).value).isEqualTo(listOf(Long.MAX_VALUE, Long.MIN_VALUE))
    }

    @Test
    fun `Double`() {
        class DoubleTest(config: Config) {
            val value: Double by config
        }
        assertThat(DoubleTest(config("value" to 1.2345)).value).isEqualTo(1.2345)
    }

    @Test
    fun `List of Double`() {
        class ListTest(config: Config) {
            val value: List<Double> by config
        }
        assertThat(ListTest(config("value" to listOf(1.2, 2.3))).value).isEqualTo(listOf(1.2, 2.3))
    }

    @Test
    fun `Boolean`() {
        class BooleanTest(config: Config) {
            val value: Boolean by config
        }
        assertThat(BooleanTest(config("value" to true)).value).isTrue()
        assertThat(BooleanTest(config("value" to false)).value).isFalse()
    }

    @Test
    fun `List of Boolean`() {
        class ListTest(config: Config) {
            val value: List<Boolean> by config
        }
        assertThat(ListTest(config("value" to listOf(true, false))).value).isEqualTo(listOf(true, false))
    }

    @Test
    fun `LocalDate`() {
        class LocalDateTest(config: Config) {
            val value: LocalDate by config
        }
        val now = LocalDate.now()
        assertThat(LocalDateTest(config("value" to now.toString())).value).isEqualTo(now)
    }

    @Test
    fun `List of LocalDate`() {
        class ListTest(config: Config) {
            val value: List<LocalDate> by config
        }
        val now = LocalDate.now()
        assertThat(ListTest(config("value" to listOf(now.toString()))).value).isEqualTo(listOf(now))
    }

    @Test
    fun `Instant`() {
        class InstantTest(config: Config) {
            val value: Instant by config
        }
        val now = Instant.now()
        assertThat(InstantTest(config("value" to now.toString())).value).isEqualTo(now)
    }

    @Test
    fun `List of Instant`() {
        class ListTest(config: Config) {
            val value: List<Instant> by config
        }
        val now = Instant.now()
        assertThat(ListTest(config("value" to listOf(now.toString()))).value).isEqualTo(listOf(now))
    }

    @Test
    fun `HostAndPort property`() {
        class HostAndPortTest(config: Config) {
            val value: HostAndPort by config
        }
        assertThat(HostAndPortTest(config("value" to "localhost:2223")).value).isEqualTo(HostAndPort.fromParts("localhost", 2223))
    }

    @Test
    fun `List of HostAndPort`() {
        class ListTest(config: Config) {
            val value: List<HostAndPort> by config
        }
        assertThat(ListTest(config("value" to listOf("localhost:2223"))).value).isEqualTo(listOf(HostAndPort.fromParts("localhost", 2223)))
    }

    @Test
    fun `Path`() {
        class PathTest(config: Config) {
            val value: Path by config
        }
        val path = Paths.get("tmp") / "test" / "file"
        assertThat(PathTest(config("value" to path.toString())).value).isEqualTo(path)
    }

    @Test
    fun `List of Path`() {
        class ListTest(config: Config) {
            val value: List<Path> by config
        }
        val path = Paths.get("tmp") / "test" / "file"
        assertThat(ListTest(config("value" to listOf(path.toString()))).value).isEqualTo(listOf(path))
    }

    @Test
    fun `URL`() {
        class URLTest(config: Config) {
            val value: URL by config
        }
        assertThat(URLTest(config("value" to "http://localhost:1234")).value).isEqualTo(URL("http://localhost:1234"))
    }

    @Test
    fun `List of URL`() {
        class ListTest(config: Config) {
            val value: List<URL> by config
        }
        assertThat(ListTest(config("value" to listOf("http://localhost:1234"))).value).isEqualTo(listOf(URL("http://localhost:1234")))
    }

    @Test
    fun `Properties `() {
        class PropertyTest(config: Config) {
            val value: Properties by config
        }
        val expected = Properties().apply { this["key"] = "value" }
        assertThat(PropertyTest(config("value" to mapOf("key" to "value"))).value).isEqualTo(expected)
    }

    @Test
    fun `List of Properties`() {
        class ListTest(config: Config) {
            val value: List<Properties> by config
        }
        val expected = listOf(
                Properties(),
                Properties().apply { this["key"] = "value" })
        assertThat(ListTest(config("value" to listOf(emptyMap(), mapOf("key" to "value")))).value).isEqualTo(expected)
    }

    @Test
    fun `data class with single property`() {
        class DataTest(config: Config) {
            val value: SingleData by config
        }
        assertThat(DataTest(config("value" to mapOf("s" to "data value"))).value).isEqualTo(SingleData("data value"))
    }

    @Test
    fun `data class with two properties`() {
        class DataTest(config: Config) {
            val value: DoubleData by config
        }
        assertThat(DataTest(config("value" to mapOf("i" to 123, "b" to true))).value).isEqualTo(DoubleData(123, true))
    }

    @Test
    fun `data class within a data class`() {
        class DataTest(config: Config) {
            val value: NestedData by config
        }
        val config = config(
                "value" to mapOf(
                        "d" to mapOf(
                                "s" to "nested")))
        assertThat(DataTest(config).value).isEqualTo(NestedData(SingleData("nested")))
    }

    @Test
    fun `List of data class`() {
        class ListTest(config: Config) {
            val value: List<SingleData> by config
        }
        val config = config(
                "value" to listOf(
                        mapOf("s" to "1"),
                        mapOf("s" to "2")))
        assertThat(ListTest(config).value).isEqualTo(listOf(SingleData("1"), SingleData("2")))
    }

    @Test
    fun `data class with a List property`() {
        class DataTest(config: Config) {
            val value: ListData by config
        }
        assertThat(DataTest(config("value" to mapOf("l" to listOf(1, 2)))).value).isEqualTo(ListData(listOf(1, 2)))
    }

    private fun config(vararg values: Pair<String, *>): Config {
        val config = ConfigValueFactory.fromMap(mapOf(*values))
        println(config.render(defaults().setOriginComments(false)))
        return config.toConfig()
    }

    data class SingleData(val s: String)
    data class DoubleData(val i: Int, val b: Boolean)
    data class NestedData(val d: SingleData)
    data class ListData(val l: List<Int>)
}