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

import de.spinscale.javalin.SecureHeadersPlugin.SecureHeaders.ClearSiteData;
import de.spinscale.javalin.SecureHeadersPlugin.SecureHeaders.CrossDomainPolicy;
import de.spinscale.javalin.SecureHeadersPlugin.SecureHeaders.CrossOriginEmbedderPolicy;
import de.spinscale.javalin.SecureHeadersPlugin.SecureHeaders.CrossOriginOpenerPolicy;
import de.spinscale.javalin.SecureHeadersPlugin.SecureHeaders.CrossOriginResourcePolicy;
import de.spinscale.javalin.SecureHeadersPlugin.SecureHeaders.ReferrerPolicy;
import de.spinscale.javalin.SecureHeadersPlugin.SecureHeaders.XFrameOptions;
import io.javalin.Javalin;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class SecureHeadersPluginTests {

    @Test
    public void testHeaderValues() {
        final SecureHeadersPlugin.SecureHeaders headers = new SecureHeadersPlugin.SecureHeaders();

        headers.xContentTypeOptionsNoSniff();
        assertThat(headers.headers()).containsEntry("X-Content-Type-Options", "nosniff");

        headers.strictTransportSecurity(Duration.ofSeconds(10), false);
        assertThat(headers.headers()).containsEntry("Strict-Transport-Security", "max-age=10");

        headers.strictTransportSecurity(Duration.ofSeconds(10), true);
        assertThat(headers.headers()).containsEntry("Strict-Transport-Security", "max-age=10 ; includeSubDomains");

        headers.xFrameOptions(XFrameOptions.DENY);
        assertThat(headers.headers()).containsEntry("X-Frame-Options", "deny");

        headers.xFrameOptions(XFrameOptions.SAMEORIGIN);
        assertThat(headers.headers()).containsEntry("X-Frame-Options", "sameorigin");

        headers.xFrameOptions("web.de");
        assertThat(headers.headers()).containsEntry("X-Frame-Options", "allow-from: web.de");

        headers.contentSecurityPolicy("foo");
        assertThat(headers.headers()).containsEntry("Content-Security-Policy", "foo");

        headers.xPermittedCrossDomainPolicies(CrossDomainPolicy.MASTER_ONLY);
        assertThat(headers.headers()).containsEntry("X-Permitted-Cross-Domain-Policies", "master-only");

        headers.xPermittedCrossDomainPolicies(CrossDomainPolicy.NONE);
        assertThat(headers.headers()).containsEntry("X-Permitted-Cross-Domain-Policies", "none");

        headers.xPermittedCrossDomainPolicies(CrossDomainPolicy.BY_CONTENT_TYPE);
        assertThat(headers.headers()).containsEntry("X-Permitted-Cross-Domain-Policies", "by-content-type");

        headers.referrerPolicy(ReferrerPolicy.STRICT_ORIGIN);
        assertThat(headers.headers()).containsEntry("Referrer-Policy", "strict-origin");

        headers.clearSiteData(ClearSiteData.ANY);
        assertThat(headers.headers()).containsEntry("Clear-Site-Data", "\"*\"");

        headers.clearSiteData(ClearSiteData.ANY, ClearSiteData.EXECUTION_CONTEXTS, ClearSiteData.STORAGE);
        assertThat(headers.headers()).containsEntry("Clear-Site-Data", "\"*\",\"executionContexts\",\"storage\"");

        headers.crossOriginEmbedderPolicy(CrossOriginEmbedderPolicy.UNSAFE_NONE);
        assertThat(headers.headers()).containsEntry("Cross-Origin-Embedder-Policy", "unsafe-none");

        headers.crossOriginOpenerPolicy(CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS);
        assertThat(headers.headers()).containsEntry("Cross-Origin-Opener-Policy", "same-origin-allow-popups");

        headers.crossOriginResourcePolicy(CrossOriginResourcePolicy.SAME_SITE);
        assertThat(headers.headers()).containsEntry("Cross-Origin-Resource-Policy", "same-site");
    }

    @Test
    void testRegisterPlugin() throws Exception {
        final SecureHeadersPlugin plugin = new SecureHeadersPlugin(headers -> {});
        final Javalin javalin = Javalin.create(config -> config.registerPlugin(plugin));

        final SecureHeadersPlugin retrievedPlugin = javalin.config.getPlugin(SecureHeadersPlugin.class);
        assertThat(retrievedPlugin).isSameAs(retrievedPlugin);
    }

    // start a javalin webserver and check if everything is working in an end to end test
    @Test
    void runFullBlownIntegrationTest() throws Exception {
        final SecureHeadersPlugin plugin = new SecureHeadersPlugin(headers -> {
            headers.xContentTypeOptionsNoSniff();
            headers.clearSiteData(ClearSiteData.ANY);
        });
        final Javalin javalin = Javalin.create(config -> config.registerPlugin(plugin));

        javalin.get("/", ctx -> {
            ctx.status(200);
        });

        OkHttpClient httpClient = null;
        javalin.start(0);

        try {
            httpClient = new OkHttpClient();
            String host = "http://localhost:" + javalin.port();
            try (Response response = httpClient.newCall(new Request.Builder().url(host + "/").build()).execute()) {
                assertThat(response.code()).isEqualTo(200);
                assertThat(response.header("X-Content-Type-Options")).isEqualTo("nosniff");
                assertThat(response.header("Clear-Site-Data")).isEqualTo("\"*\"");
            }
        } finally {
            javalin.stop();
            if (httpClient != null) {
                httpClient.dispatcher().executorService().shutdown();
                httpClient.connectionPool().evictAll();
            }
        }
    }
}