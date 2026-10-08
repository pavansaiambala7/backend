package com.backend.auth.clientapp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * A tiny HTTP server on a random loopback port, standing in for the authorization server's token
 * endpoint and the orders API. It records every request so tests can check what the BFF sent.
 */
final class FakeHttpServer implements AutoCloseable {

    private final HttpServer server;
    private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();
    private final Map<String, Function<RecordedRequest, Response>> routes = new ConcurrentHashMap<>();

    private FakeHttpServer(HttpServer server) {
        this.server = server;
        server.createContext("/", this::handle);
        server.start();
    }

    static FakeHttpServer start() {
        try {
            return new FakeHttpServer(HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0));
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    void respond(String path, Function<RecordedRequest, Response> handler) {
        routes.put(path, handler);
    }

    List<RecordedRequest> requestsTo(String path) {
        return requests.stream().filter(request -> request.path().equals(path)).toList();
    }

    void reset() {
        routes.clear();
        requests.clear();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange; InputStream in = exchange.getRequestBody()) {
            RecordedRequest request = new RecordedRequest(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(),
                    exchange.getRequestHeaders().getFirst("Authorization"),
                    new String(in.readAllBytes(), StandardCharsets.UTF_8));
            requests.add(request);

            Response response = routes.getOrDefault(request.path(), r -> new Response(404, "{}", Map.of())).apply(request);
            byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            response.headers().forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
            exchange.sendResponseHeaders(response.status(), body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    record RecordedRequest(String method, String path, String authorization, String body) {
    }

    record Response(int status, String body, Map<String, String> headers) {

        static Response json(String body) {
            return new Response(200, body, Map.of());
        }
    }
}
