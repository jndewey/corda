// TODO: Remove when configureTestSSL() is moved.
@file:JvmName("ConfigUtilities")

package net.corda.node.services.config

import com.google.common.net.HostAndPort
import com.typesafe.config.*
import net.corda.core.copyTo
import net.corda.core.createDirectories
import net.corda.core.crypto.X509Utilities
import net.corda.core.div
import net.corda.core.exists
import net.corda.core.utilities.loggerFor
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.time.LocalDate
import java.util.*
import kotlin.reflect.KProperty
import kotlin.reflect.jvm.javaType

object ConfigHelper {
    val log = loggerFor<ConfigHelper>()

    fun loadConfig(baseDirectoryPath: Path,
                   configFileOverride: Path? = null,
                   allowMissingConfig: Boolean = false,
                   configOverrides: Map<String, Any?> = emptyMap()): Config {

        val defaultConfig = ConfigFactory.parseResources("reference.conf", ConfigParseOptions.defaults().setAllowMissing(false))

        val normalisedBaseDir = baseDirectoryPath.normalize()
        val configFile = (configFileOverride?.normalize() ?: normalisedBaseDir / "node.conf").toFile()
        val appConfig = ConfigFactory.parseFile(configFile, ConfigParseOptions.defaults().setAllowMissing(allowMissingConfig))

        val overridesMap = HashMap<String, Any?>() // If we do require a few other command line overrides eg for a nicer development experience they would go inside this map.
        overridesMap.putAll(configOverrides)
        overridesMap["basedir"] = normalisedBaseDir.toAbsolutePath().toString()
        val overrideConfig = ConfigFactory.parseMap(overridesMap)

        val mergedAndResolvedConfig = overrideConfig.withFallback(appConfig).withFallback(defaultConfig).resolve()
        log.info("Config:\n ${mergedAndResolvedConfig.root().render(ConfigRenderOptions.defaults())}")
        return mergedAndResolvedConfig
    }
}

operator fun <T> Config.getValue(receiver: Any, metadata: KProperty<*>): T {
    return getValueInternal(metadata.name, metadata.returnType.javaType)
}

@Suppress("UNCHECKED_CAST")
private fun <T> Config.getValueInternal(path: String, type: Type): T {
    return when (type) {
        String::class.java -> getString(path)
        Int::class.java -> getInt(path)
        Long::class.java -> getLong(path)
        Double::class.java -> getDouble(path)
        Boolean::class.java -> getBoolean(path)
        LocalDate::class.java -> LocalDate.parse(getString(path))
        Instant::class.java -> Instant.parse(getString(path))
        HostAndPort::class.java -> HostAndPort.fromString(getString(path))
        Path::class.java -> Paths.get(getString(path))
        URL::class.java -> URL(getString(path))
        Properties::class.java -> getObject(path).toProperties()
        is ParameterizedType -> getParameterisedValue<T>(path, type)
        else -> getConfig(path).toObjectGraph(type as Class<*>)
    } as T
}

@Suppress("UNCHECKED_CAST", "PLATFORM_CLASS_MAPPED_TO_KOTLIN")
private fun <T> Config.getParameterisedValue(path: String, type: ParameterizedType): T {
    val rawType = type.rawType as Class<*>
    require(Collection::class.java.isAssignableFrom(rawType)) { "$rawType is not supported" }
    val argType = type.actualTypeArguments[0] as Class<*>
    val values: List<Any> = when (argType) {
        String::class.java -> getStringList(path)
        Integer::class.java -> getIntList(path)
        java.lang.Long::class.java -> getLongList(path)
        java.lang.Double::class.java -> getDoubleList(path)
        java.lang.Boolean::class.java -> getBooleanList(path)
        LocalDate::class.java -> getStringList(path).map { LocalDate.parse(it) }
        Instant::class.java -> getStringList(path).map { Instant.parse(it) }
        HostAndPort::class.java -> getStringList(path).map { HostAndPort.fromString(it) }
        Path::class.java -> getStringList(path).map { Paths.get(it) }
        URL::class.java -> getStringList(path).map(::URL)
        Properties::class.java -> getObjectList(path).map { it.toProperties() }
        else -> getConfigList(path).map { it.toObjectGraph(argType) }
    }
    return when (rawType) {
        List::class.java -> values
        Set::class.java -> values.toSet()
        else -> throw IllegalArgumentException("$rawType is not supported")
    } as T
}

fun <T : Any> Config.toObjectGraph(type: Class<T>): T {
    val constructor = type.kotlin.constructors.maxBy { it.parameters.size }
            ?: throw IllegalArgumentException("${type.name} has no constructors")
    val args = constructor.parameters
            .filterNot { it.isOptional && !hasPath(it.name!!) }
            .associateBy({ it }) { getValueInternal<Any>(it.name!!, it.type.javaType) }
    return constructor.callBy(args)
}

/**
 * Helper class for optional configurations
 */
class OptionalConfig<out T>(val config: Config, val default: () -> T) {
    operator fun getValue(receiver: Any, metadata: KProperty<*>): T {
        return if (config.hasPath(metadata.name)) config.getValue(receiver, metadata) else default()
    }
}

fun <T> Config.orElse(default: () -> T): OptionalConfig<T> = OptionalConfig(this, default)

private fun ConfigObject.toProperties(): Properties = this.mapValuesTo(Properties()) { it.value.unwrapped().toString() }

@Suppress("UNCHECKED_CAST")
inline fun <reified T : Any> Config.getListOrElse(path: String, default: Config.() -> List<T>): List<T> {
    return if (hasPath(path)) {
        (if (T::class == String::class) getStringList(path) else getConfigList(path)) as List<T>
    } else {
        this.default()
    }
}

/**
 * Strictly for dev only automatically construct a server certificate/private key signed from
 * the CA certs in Node resources. Then provision KeyStores into certificates folder under node path.
 */
fun NodeConfiguration.configureWithDevSSLCertificate() = configureDevKeyAndTrustStores(myLegalName)

private fun NodeSSLConfiguration.configureDevKeyAndTrustStores(myLegalName: String) {
    certificatesPath.createDirectories()
    if (!trustStorePath.exists()) {
        javaClass.classLoader.getResourceAsStream("net/corda/node/internal/certificates/cordatruststore.jks").copyTo(trustStorePath)
    }
    if (!keyStorePath.exists()) {
        val caKeyStore = X509Utilities.loadKeyStore(
                javaClass.classLoader.getResourceAsStream("net/corda/node/internal/certificates/cordadevcakeys.jks"),
                "cordacadevpass")
        X509Utilities.createKeystoreForSSL(keyStorePath, keyStorePassword, keyStorePassword, caKeyStore, "cordacadevkeypass", myLegalName)
    }
}

// TODO Move this to CoreTestUtils.kt once we can pry this from the explorer
@JvmOverloads
fun configureTestSSL(legalName: String = "Mega Corp."): NodeSSLConfiguration = object : NodeSSLConfiguration {
    override val certificatesPath = Files.createTempDirectory("certs")
    override val keyStorePassword: String get() = "cordacadevpass"
    override val trustStorePassword: String get() = "trustpass"

    init {
        configureDevKeyAndTrustStores(legalName)
    }
}
