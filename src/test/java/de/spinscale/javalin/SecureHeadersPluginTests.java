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

import de.spinscale.javalin.SecureHeadersPlugin.Builder.ClearSiteData;
import de.spinscale.javalin.SecureHeadersPlugin.Builder.CrossDomainPolicy;
import de.spinscale.javalin.SecureHeadersPlugin.Builder.CrossOriginEmbedderPolicy;
import de.spinscale.javalin.SecureHeadersPlugin.Builder.CrossOriginOpenerPolicy;
import de.spinscale.javalin.SecureHeadersPlugin.Builder.CrossOriginResourcePolicy;
import de.spinscale.javalin.SecureHeadersPlugin.Builder.ReferrerPolicy;
import io.javalin.Javalin;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecureHeadersPluginTests {

    @Test
    public void testHeaderValues() {
        final SecureHeadersPlugin.Builder builder = SecureHeadersPlugin.builder();

        builder.xContentTypeOptionsNoSniff();
        assertThat(builder.headers()).containsEntry("X-Content-Type-Options", "nosniff");

        builder.strictTransportSecurity(Duration.ofSeconds(10), false);
        assertThat(builder.headers()).containsEntry("Strict-Transport-Security", "max-age=10");

        builder.strictTransportSecurity(Duration.ofSeconds(10), true);
        assertThat(builder.headers()).containsEntry("Strict-Transport-Security", "max-age=10 ; includeSubDomains");

        builder.xFrameOptions("deny");
        assertThat(builder.headers()).containsEntry("X-Frame-Options", "deny");

        builder.xFrameOptions("sameorigin");
        assertThat(builder.headers()).containsEntry("X-Frame-Options", "sameorigin");

        builder.xFrameOptions("allow-from: web.de");
        assertThat(builder.headers()).containsEntry("X-Frame-Options", "allow-from: web.de");

        assertThatThrownBy(() -> builder.xFrameOptions("invalid"))
                .hasMessage("X-Frame-Options must be deny | sameorigin | allow-from: DOMAIN");

        builder.contentSecurityPolicy("foo");
        assertThat(builder.headers()).containsEntry("Content-Security-Policy", "foo");

        builder.xPermittedCrossDomainPolicies(CrossDomainPolicy.MASTER_ONLY);
        assertThat(builder.headers()).containsEntry("X-Permitted-Cross-Domain-Policies", "master-only");

        builder.xPermittedCrossDomainPolicies(CrossDomainPolicy.NONE);
        assertThat(builder.headers()).containsEntry("X-Permitted-Cross-Domain-Policies", "none");

        builder.xPermittedCrossDomainPolicies(CrossDomainPolicy.BY_CONTENT_TYPE);
        assertThat(builder.headers()).containsEntry("X-Permitted-Cross-Domain-Policies", "by-content-type");

        builder.referrerPolicy(ReferrerPolicy.STRICT_ORIGIN);
        assertThat(builder.headers()).containsEntry("Referrer-Policy", "strict-origin");

        builder.clearSiteData(ClearSiteData.ANY);
        assertThat(builder.headers()).containsEntry("Clear-Site-Data", "\"*\"");

        builder.clearSiteData(ClearSiteData.ANY, ClearSiteData.EXECUTION_CONTEXTS, ClearSiteData.STORAGE);
        assertThat(builder.headers()).containsEntry("Clear-Site-Data", "\"*\",\"executionContexts\",\"storage\"");

        builder.crossOriginEmbedderPolicy(CrossOriginEmbedderPolicy.UNSAFE_NONE);
        assertThat(builder.headers()).containsEntry("Cross-Origin-Embedder-Policy", "unsafe-none");

        builder.crossOriginOpenerPolicy(CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS);
        assertThat(builder.headers()).containsEntry("Cross-Origin-Opener-Policy", "same-origin-allow-popups");

        builder.crossOriginResourcePolicy(CrossOriginResourcePolicy.SAME_SITE);
        assertThat(builder.headers()).containsEntry("Cross-Origin-Resource-Policy", "same-site");
    }

    @Test
    void testRegisterPlugin() throws Exception {
        final SecureHeadersPlugin plugin = SecureHeadersPlugin.builder().build();
        final Javalin javalin = Javalin.create(config -> config.registerPlugin(plugin));

        final SecureHeadersPlugin retrievedPlugin = javalin.config.getPlugin(SecureHeadersPlugin.class);
        assertThat(retrievedPlugin).isSameAs(retrievedPlugin);
    }

    // start a javalin webserver and check if everything is working in an end to end test
    @Test
    void runFullBlownIntegrationTest() throws Exception {
        final SecureHeadersPlugin plugin = SecureHeadersPlugin.builder()
                .xContentTypeOptionsNoSniff()
                .clearSiteData(ClearSiteData.ANY)
                .build();
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