package com.backend.auth.apikeys.security;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

/**
 * Writes RFC 9457 problem responses from security filters, which run before Spring MVC and its
 * {@code ProblemDetail} support. Bodies never echo request data back.
 */
@Component
public class ProblemWriter {

    private final JsonMapper json;

    ProblemWriter(JsonMapper json) {
        this.json = json;
    }

    public void write(HttpServletResponse response, HttpStatus status, String title, String detail) throws IOException {
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("title", title);
        problem.put("status", status.value());
        problem.put("detail", detail);
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        json.writeValue(response.getOutputStream(), problem);
    }
}
