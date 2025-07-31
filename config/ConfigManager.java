package config;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class ConfigManager {
    private static final Logger logger = Logger.getLogger(ConfigManager.class.getName());
    private static final String DEFAULT_CONFIG_FILE = "server.properties";

    private final Properties properties;
    private final Map<String, String> cache;
    private final File configFile;

    // Default configuration values
    private static final Map<String, String> DEFAULTS = new HashMap<>();
    static {
        // Server configuration
        DEFAULTS.put("server.port", "23068");
        DEFAULTS.put("server.host", "0.0.0.0");
        DEFAULTS.put("server.thread.pool.size", "10");
        DEFAULTS.put("server.thread.pool.max", "50");
        DEFAULTS.put("server.backlog", "50");
        DEFAULTS.put("server.socket.timeout", "300000");

        // SSL/TLS configuration
        DEFAULTS.put("ssl.protocol", "TLSv1.3");
        DEFAULTS.put("ssl.keystore.path", "resources/server/server-keystore.p12");
        DEFAULTS.put("ssl.keystore.password", "changeit");
        DEFAULTS.put("ssl.truststore.path", "resources/server/server-truststore.p12");
        DEFAULTS.put("ssl.truststore.password", "changeit");
        DEFAULTS.put("ssl.client.auth", "true");

        // Storage configuration
        DEFAULTS.put("storage.path", "server_data/");
        DEFAULTS.put("storage.max.file.size", "104857600"); // 100MB
        DEFAULTS.put("storage.temp.path", "server_data/temp/");

        // Security configuration
        DEFAULTS.put("security.pbkdf2.iterations", "100000");
        DEFAULTS.put("security.salt.length", "32");
        DEFAULTS.put("security.session.timeout", "3600000"); // 1 hour
        DEFAULTS.put("security.max.login.attempts", "5");
        DEFAULTS.put("security.lockout.duration", "300000"); // 5 minutes

        // Rate limiting
        DEFAULTS.put("ratelimit.enabled", "true");
        DEFAULTS.put("ratelimit.requests.per.minute", "60");
        DEFAULTS.put("ratelimit.requests.per.hour", "1000");

        // Logging configuration
        DEFAULTS.put("logging.level", "INFO");
        DEFAULTS.put("logging.file", "server.log");
        DEFAULTS.put("logging.max.size", "10485760"); // 10MB
        DEFAULTS.put("logging.max.files", "10");

        // Client configuration defaults
        DEFAULTS.put("client.timeout", "30000");
        DEFAULTS.put("client.retry.attempts", "3");
        DEFAULTS.put("client.retry.delay", "1000");

        // Performance tuning
        DEFAULTS.put("performance.buffer.size", "8192");
        DEFAULTS.put("performance.cache.enabled", "true");
        DEFAULTS.put("performance.cache.size", "1000");
        DEFAULTS.put("performance.cache.ttl", "300000"); // 5 minutes
    }

    public ConfigManager() {
        this(DEFAULT_CONFIG_FILE);
    }

    public ConfigManager(String configPath) {
        this.configFile = new File(configPath);
        this.properties = new Properties();
        this.cache = new ConcurrentHashMap<>();

        loadConfiguration();
    }

    private void loadConfiguration() {
        // First, load defaults
        DEFAULTS.forEach((key, value) -> properties.setProperty(key, value));

        // Then, load from file if exists
        if (configFile.exists()) {
            try (InputStream input = new FileInputStream(configFile)) {
                properties.load(input);
                logger.info("Configuration loaded from: " + configFile.getAbsolutePath());
            } catch (IOException e) {
                logger.warning("Failed to load configuration file: " + e.getMessage());
            }
        } else {
            logger.info("No configuration file found, using defaults");
            saveConfiguration(); // Save defaults to file
        }

        // Load environment variable overrides
        loadEnvironmentOverrides();
    }

    private void loadEnvironmentOverrides() {
        // Allow environment variables to override configuration
        // Format: FILESERVER_SECTION_KEY (e.g., FILESERVER_SERVER_PORT)
        System.getenv().forEach((key, value) -> {
            if (key.startsWith("FILESERVER_")) {
                String configKey = key.substring(11).toLowerCase().replace('_', '.');
                properties.setProperty(configKey, value);
                logger.info("Environment override: " + configKey + " = " + value);
            }
        });
    }

    public void saveConfiguration() {
        try {
            // Ensure directory exists
            configFile.getParentFile().mkdirs();

            try (OutputStream output = new FileOutputStream(configFile)) {
                properties.store(output, "File Server Configuration");
                logger.info("Configuration saved to: " + configFile.getAbsolutePath());
            }
        } catch (IOException e) {
            logger.severe("Failed to save configuration: " + e.getMessage());
        }
    }

    // Get configuration value as String
    public String getString(String key) {
        return getString(key, null);
    }

    public String getString(String key, String defaultValue) {
        // Check cache first
        String cachedValue = cache.get(key);
        if (cachedValue != null) {
            return cachedValue;
        }

        String value = properties.getProperty(key, defaultValue);
        if (value != null) {
            cache.put(key, value);
        }
        return value;
    }

    // Get configuration value as integer
    public int getInt(String key) {
        return getInt(key, 0);
    }

    public int getInt(String key, int defaultValue) {
        String value = getString(key);
        if (value == null) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            logger.warning("Invalid integer value for " + key + ": " + value);
            return defaultValue;
        }
    }

    // Get configuration value as long
    public long getLong(String key) {
        return getLong(key, 0L);
    }

    public long getLong(String key, long defaultValue) {
        String value = getString(key);
        if (value == null) {
            return defaultValue;
        }

        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            logger.warning("Invalid long value for " + key + ": " + value);
            return defaultValue;
        }
    }

    // Get configuration value as boolean
    public boolean getBoolean(String key) {
        return getBoolean(key, false);
    }

    public boolean getBoolean(String key, boolean defaultValue) {
        String value = getString(key);
        if (value == null) {
            return defaultValue;
        }

        return Boolean.parseBoolean(value);
    }

    // Get configuration value as list
    public List<String> getList(String key) {
        return getList(key, ",");
    }

    public List<String> getList(String key, String delimiter) {
        String value = getString(key);
        if (value == null || value.trim().isEmpty()) {
            return Collections.emptyList();
        }

        return Arrays.asList(value.split(delimiter));
    }

    // Set configuration value
    public void set(String key, String value) {
        properties.setProperty(key, value);
        cache.put(key, value);
    }

    public void setInt(String key, int value) {
        set(key, String.valueOf(value));
    }

    public void setLong(String key, long value) {
        set(key, String.valueOf(value));
    }

    public void setBoolean(String key, boolean value) {
        set(key, String.valueOf(value));
    }

    // Remove configuration value
    public void remove(String key) {
        properties.remove(key);
        cache.remove(key);
    }

    // Clear cache
    public void clearCache() {
        cache.clear();
    }

    // Get all keys
    public Set<String> getKeys() {
        return properties.stringPropertyNames();
    }

    // Get all keys with prefix
    public Set<String> getKeys(String prefix) {
        Set<String> keys = new HashSet<>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(prefix)) {
                keys.add(key);
            }
        }
        return keys;
    }

    // Reload configuration
    public void reload() {
        cache.clear();
        properties.clear();
        loadConfiguration();
        logger.info("Configuration reloaded");
    }

    // Validate configuration
    public List<String> validate() {
        List<String> errors = new ArrayList<>();

        // Validate port number
        int port = getInt("server.port", -1);
        if (port < 1 || port > 65535) {
            errors.add("Invalid server port: " + port);
        }

        // Validate file paths
        String keystorePath = getString("ssl.keystore.path");
        if (keystorePath != null && !new File(keystorePath).exists()) {
            errors.add("Keystore file not found: " + keystorePath);
        }

        String truststorePath = getString("ssl.truststore.path");
        if (truststorePath != null && !new File(truststorePath).exists()) {
            errors.add("Truststore file not found: " + truststorePath);
        }

        // Validate numeric values
        if (getInt("server.thread.pool.size") <= 0) {
            errors.add("Invalid thread pool size");
        }

        if (getLong("storage.max.file.size") <= 0) {
            errors.add("Invalid max file size");
        }

        return errors;
    }

    // Export configuration
    public void exportTo(String filePath) throws IOException {
        try (OutputStream output = new FileOutputStream(filePath)) {
            properties.store(output, "Exported Configuration");
        }
    }

    // Import configuration
    public void importFrom(String filePath) throws IOException {
        Properties importedProps = new Properties();
        try (InputStream input = new FileInputStream(filePath)) {
            importedProps.load(input);
        }

        // Merge with existing properties
        importedProps.forEach((key, value) -> properties.setProperty(key.toString(), value.toString()));
        cache.clear();

        logger.info("Configuration imported from: " + filePath);
    }

    // Configuration builder for programmatic setup
    public static class Builder {
        private final ConfigManager config;

        public Builder() {
            this.config = new ConfigManager();
        }

        public Builder withServerPort(int port) {
            config.setInt("server.port", port);
            return this;
        }

        public Builder withThreadPoolSize(int size) {
            config.setInt("server.thread.pool.size", size);
            return this;
        }

        public Builder withSSLKeystore(String path, String password) {
            config.set("ssl.keystore.path", path);
            config.set("ssl.keystore.password", password);
            return this;
        }

        public Builder withSSLTruststore(String path, String password) {
            config.set("ssl.truststore.path", path);
            config.set("ssl.truststore.password", password);
            return this;
        }

        public Builder withStoragePath(String path) {
            config.set("storage.path", path);
            return this;
        }

        public Builder withMaxFileSize(long size) {
            config.setLong("storage.max.file.size", size);
            return this;
        }

        public Builder withRateLimiting(boolean enabled, int requestsPerMinute) {
            config.setBoolean("ratelimit.enabled", enabled);
            config.setInt("ratelimit.requests.per.minute", requestsPerMinute);
            return this;
        }

        public ConfigManager build() {
            return config;
        }
    }

    // Singleton instance for global access
    private static ConfigManager instance;

    public static synchronized ConfigManager getInstance() {
        if (instance == null) {
            instance = new ConfigManager();
        }
        return instance;
    }

    public static synchronized void setInstance(ConfigManager config) {
        instance = config;
    }
}