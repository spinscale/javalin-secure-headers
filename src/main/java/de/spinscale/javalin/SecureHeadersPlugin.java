/*
 * Copyright [2019] [Alexander Reelsen]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package de.spinscale.javalin;

import io.javalin.Javalin;
import io.javalin.core.plugin.Plugin;
import org.jetbrains.annotations.NotNull;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * A plugin to configure secure headers according to the OWASP secure headers project
 * https://owasp.org/www-project-secure-headers/
 */
public class SecureHeadersPlugin implements Plugin {

    private final Map<String, String> headers;

    public SecureHeadersPlugin(Consumer<SecureHeaders> consumer) {
        SecureHeaders secureHeaders = new SecureHeaders();
        consumer.accept(secureHeaders);
        this.headers = secureHeaders.headers();
    }

    @Override
    public void apply(@NotNull Javalin app) {
        app.after(ctx -> headers.forEach(ctx::header));
    }

    public static final class SecureHeaders {

        private Map<String, String> headers = new HashMap<>(10);

        // visible for testing
        Map<String, String> headers() {
            return Collections.unmodifiableMap(headers);
        }

        // Strict-Transport-Security: max-age=31536000 ; includeSubDomains
        public void strictTransportSecurity(Duration duration, boolean includeSubdomains) {
            if (includeSubdomains) {
                headers.put("Strict-Transport-Security", "max-age=" + duration.getSeconds() + " ; includeSubDomains");
            } else {
                headers.put("Strict-Transport-Security", "max-age=" + duration.getSeconds());
            }
        }

        // X-Frame-Options: deny | sameorigin | allow-from: DOMAIN
        public enum XFrameOptions { DENY, SAMEORIGIN;
            private String headerValue() {
                return name().toLowerCase(Locale.ROOT).replaceAll("_", "-");
            }
        }

        public void xFrameOptions(XFrameOptions xFrameOptions) {
            headers.put("X-Frame-Options", xFrameOptions.headerValue());
        }

        public void xFrameOptions(String domain) {
            headers.put("X-Frame-Options", "allow-from: " + domain);
        }

        // X-Content-Type-Options: nosniff
        public void xContentTypeOptionsNoSniff() {
            headers.put("X-Content-Type-Options", "nosniff");
        }

        // Content-Security-Policy: String... + JAVADOC
        public void contentSecurityPolicy(String contentSecurityPolicy) {
            headers.put("Content-Security-Policy", contentSecurityPolicy);
        }

        // X-Permitted-Cross-Domain-Policies: none | master-only | by-content-type | by-ftp-filename | all
        public enum CrossDomainPolicy { NONE, MASTER_ONLY, BY_CONTENT_TYPE, BY_FTP_FILENAME, ALL;
            private String headerValue() {
                return name().toLowerCase(Locale.ROOT).replaceAll("_", "-");
            }
        }
        public void xPermittedCrossDomainPolicies(CrossDomainPolicy policy) {
            headers.put("X-Permitted-Cross-Domain-Policies", policy.headerValue());
        }

        // Referrer-Policy: no-referrer | no-referrer-when-downgrade | origin | origin-when-cross-origin | same-origin | strict-origin | strict-origin-when-cross-origin | unsafe-url
        public enum ReferrerPolicy { NO_REFERRER, NO_REFERRER_WHEN_DOWNGRADE, ORIGIN, ORIGIN_WHEN_CROSS_ORIGIN, SAME_ORIGIN, STRICT_ORIGIN, STRICT_ORIGIN_WHEN_CROSS_ORIGIN, UNSAFE_URL;
            private String headerValue() {
                return name().toLowerCase(Locale.ROOT).replaceAll("_", "-");
            }
        }

        public void referrerPolicy(ReferrerPolicy policy) {
            headers.put("Referrer-Policy", policy.headerValue());
        }

        // Clear-Site-Data: "cache" | "cookies" | "storage" | "executionContexts" | "*"
        public enum ClearSiteData { CACHE, COOKIES, STORAGE, EXECUTION_CONTEXTS, ANY;
            private String headerValue() {
                if (this == ANY) {
                    return "\"*\"";
                }
                if (this == EXECUTION_CONTEXTS) {
                    return "\"executionContexts\"";
                }
                return "\"" + name().toLowerCase(Locale.ROOT) + "\"";
            }
        }
        public void clearSiteData(ClearSiteData... data) {
            String value = Arrays.stream(data).map(ClearSiteData::headerValue).collect(Collectors.joining(","));
            headers.put("Clear-Site-Data", value);
        }

        // Cross-Origin-Embedder-Policy: require-corp | unsafe-none
        public enum CrossOriginEmbedderPolicy { UNSAFE_NONE, REQUIRE_CORP;
            private String headerValue() {
                return name().toLowerCase(Locale.ROOT).replaceAll("_", "-");
            }
        }

        public void crossOriginEmbedderPolicy(CrossOriginEmbedderPolicy policy) {
            headers.put("Cross-Origin-Embedder-Policy", policy.headerValue());
        }

        // Cross-Origin-Opener-Policy: unsafe-none	| same-origin-allow-popups	| same-origin
        public enum CrossOriginOpenerPolicy { UNSAFE_NONE, SAME_ORIGIN_ALLOW_POPUPS, SAME_ORIGIN;
            private String headerValue() {
                return name().toLowerCase(Locale.ROOT).replaceAll("_", "-");
            }
        }

        public void crossOriginOpenerPolicy(CrossOriginOpenerPolicy policy) {
            headers.put("Cross-Origin-Opener-Policy", policy.headerValue());
        }

        // Cross-Origin-Resource-Policy: same-site	| same-origin | cross-origin
        public enum CrossOriginResourcePolicy { SAME_SITE, SAME_ORIGIN, CROSS_ORIGIN;
            private String headerValue() {
                return name().toLowerCase(Locale.ROOT).replaceAll("_", "-");
            }
        }

        public void crossOriginResourcePolicy(CrossOriginResourcePolicy policy) {
            headers.put("Cross-Origin-Resource-Policy", policy.headerValue());
        }
    }
}
