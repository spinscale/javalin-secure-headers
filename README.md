# Javalin Secure Headers Plugin

A Javalin plugin to configure secure headers according to the [OWASP Secure
Headers Project](https://owasp.org/www-project-secure-headers/).

```java
final SecureHeadersPlugin plugin = new SecureHeadersPlugin(headers -> {
        headers.xContentTypeOptionsNoSniff();
        headers.strictTransportSecurity(Duration.ofSeconds(10), true);
        headers.xFrameOptions("deny");
        headers.xPermittedCrossDomainPolicies(CrossDomainPolicy.NONE);
        headers.referrerPolicy(ReferrerPolicy.STRICT_ORIGIN);
        headers.clearSiteData(ClearSiteData.COOKIES, ClearSiteData.EXECUTION_CONTEXTS, ClearSiteData.STORAGE);
        headers.crossOriginEmbedderPolicy(CrossOriginEmbedderPolicy.UNSAFE_NONE);
        headers.crossOriginOpenerPolicy(CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS);
        headers.crossOriginResourcePolicy(CrossOriginResourcePolicy.SAME_SITE);
    })

final Javalin javalin = Javalin.create(config -> config.registerPlugin(plugin));
```

## Development

Ensure code coverage, run `./gradlew clean test jacocoTestReport`

When opening pull requests, please ensure, you added a test.

