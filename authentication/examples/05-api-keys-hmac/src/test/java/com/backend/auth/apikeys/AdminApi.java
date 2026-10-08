package com.backend.auth.apikeys;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.jayway.jsonpath.JsonPath;

/** Drives the admin API the way an administrator would, with the DEMO accounts from application.yml. */
public final class AdminApi {

    public record CreatedKey(String id, String key, String prefix) {
    }

    private AdminApi() {
    }

    public static RequestPostProcessor acmeAdmin() {
        return httpBasic("acme-admin", "acme-admin-demo-passphrase");
    }

    public static RequestPostProcessor globexAdmin() {
        return httpBasic("globex-admin", "globex-admin-demo-passphrase");
    }

    public static String bearer(String apiKey) {
        return "Bearer " + apiKey;
    }

    /** Creates a key for the "acme" account with the default lifetime. */
    public static CreatedKey createKey(MockMvc mvc, String... scopes) throws Exception {
        return createKey(mvc, acmeAdmin(), null, scopes);
    }

    public static CreatedKey createKey(MockMvc mvc, RequestPostProcessor admin, Integer expiresInDays, String... scopes)
            throws Exception {
        StringBuilder body = new StringBuilder("{\"name\":\"test key\",\"scopes\":[");
        for (int i = 0; i < scopes.length; i++) {
            body.append(i == 0 ? "" : ",").append('"').append(scopes[i]).append('"');
        }
        body.append(']');
        if (expiresInDays != null) {
            body.append(",\"expiresInDays\":").append(expiresInDays);
        }
        body.append('}');

        String json = mvc.perform(post("/admin/api-keys").with(admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body.toString()))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return new CreatedKey(JsonPath.read(json, "$.id"), JsonPath.read(json, "$.key"), JsonPath.read(json, "$.prefix"));
    }
}
