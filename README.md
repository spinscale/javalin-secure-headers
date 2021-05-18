# Javalin Secure Headers Plugin

A Javalin plugin to configure secure headers according to the [OWASP Secure
Headers Project](https://owasp.org/www-project-secure-headers/).

```java
final SecureHeadersPlugin plugin = SecureHeadersPlugin.builder()
        .xContentTypeOptionsNoSniff();
        .strictTransportSecurity(Duration.ofSeconds(10), true)
        .xFrameOptions("deny")
        .xPermittedCrossDomainPolicies(CrossDomainPolicy.NONE)
        .referrerPolicy(ReferrerPolicy.STRICT_ORIGIN)
        .clearSiteData(ClearSiteData.COOKIES, ClearSiteData.EXECUTION_CONTEXTS, ClearSiteData.STORAGE)
        .crossOriginEmbedderPolicy(CrossOriginEmbedderPolicy.UNSAFE_NONE)
        .crossOriginOpenerPolicy(CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS)
        .crossOriginResourcePolicy(CrossOriginResourcePolicy.SAME_SITE)
        .build();

final Javalin javalin = Javalin.create(config -> config.registerPlugin(plugin));
```

## Development

Ensure code coverage, run `./gradlew clean test jacocoTestReport`

When opening pull requests, please ensure, you added a test.

