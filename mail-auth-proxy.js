const http = require("node:http");
const crypto = require("node:crypto");

const token = process.env.MCP_PROXY_TOKEN;

if (!token) {
  console.error("MCP_PROXY_TOKEN is not configured");
  process.exit(1);
}

function isAuthorized(header) {
  const expected = Buffer.from(`Bearer ${token}`);
  const actual = Buffer.from(header || "");

  return (
    actual.length === expected.length &&
    crypto.timingSafeEqual(actual, expected)
  );
}

const server = http.createServer((req, res) => {
  if (!isAuthorized(req.headers.authorization)) {
    res.writeHead(401, {
      "Content-Type": "text/plain",
      "WWW-Authenticate": 'Bearer realm="mail-mcp"',
    });
    res.end("Unauthorized");
    return;
  }

  const headers = { ...req.headers };
  delete headers.authorization;
  delete headers.connection;

  const upstream = http.request(
    {
      hostname: "127.0.0.1",
      port: 9557,
      path: req.url,
      method: req.method,
      headers,
    },
    (upstreamResponse) => {
      const responseHeaders = { ...upstreamResponse.headers };
      delete responseHeaders.connection;

      res.writeHead(upstreamResponse.statusCode, responseHeaders);
      upstreamResponse.pipe(res);
    }
  );

  upstream.on("error", () => {
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "text/plain" });
      res.end("Mail MCP unavailable");
    } else {
      res.destroy();
    }
  });

  req.on("aborted", () => upstream.destroy());
  res.on("close", () => {
    if (!res.writableEnded) upstream.destroy();
  });

  req.pipe(upstream);
});

server.listen(8000, "0.0.0.0", () => {
  console.log("Mail MCP authorization proxy listening on port 8000");
});
