const http = require('http');

let cachedContent = "Hello, world! This is cached content.";

const server = http.createServer((req, res) => {
  const overriddenMethod = req.headers['x-http-method-override'];
  const method = (overriddenMethod || req.method).toUpperCase();

  if (method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(cachedContent);

  } else if (method === 'PURGE') {
    cachedContent = '';
    console.log(`PURGE received for: ${req.url}`);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Cache purged');
  } else {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end(`${method} not supported.`);
  }
});

server.listen(3000, () => {
  console.log('Server listening on http://localhost:3000');
});
