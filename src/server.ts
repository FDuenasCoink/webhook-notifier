import express from 'express';
import http from 'node:http';
import crypto from 'node:crypto';
import { Server } from 'socket.io';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  transports: ['websocket'],
});

const PORT = process.env.PORT || 3_000;
const WEBHOOK_SECRET_KEY = process.env.WEBHOOK_SECRET_KEY || "YOUR_WEBHOOK_SECRET_KEY";

app.use(
  express.json({
    verify: (req, _res, buf, encoding: BufferEncoding) => {
      if (buf?.length) {
        (req as any)['rawBody'] = buf.toString(encoding || 'utf8');
      }
    }
  })
);

app.get('/', (_req, res) => {
  res.send(`
    <h1>webhook notifier api</h1>
  `)
});

app.post('/webhook', (req, res) => {
  try {
    const signature = req.get("X-Signature");
    const timestamp = req.get("X-Timestamp");
    const rawBody = (req as any).rawBody;

    if (!signature || !timestamp || !rawBody || !WEBHOOK_SECRET_KEY) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET_KEY);
    const expectedSignature = hmac.update(rawBody).digest("hex");

    const expectedSignatureBuffer = Buffer.from(expectedSignature, "utf8");
    const providedSignatureBuffer = Buffer.from(signature, "utf8");

    if (
      expectedSignatureBuffer.length !== providedSignatureBuffer.length || 
      !crypto.timingSafeEqual(expectedSignatureBuffer, providedSignatureBuffer)
    ) {
      res.status(401).json({
        message: 'Invalid signature',
      });
      return;
    }

    const jsonBody = JSON.parse(rawBody);

    io.to(jsonBody.session_id).emit(
      'status_change',
      rawBody,
    );

    res.json({ message: "Webhook event dispatched" });
  } catch {
    res.status(401).json({ message: "Unauthorized" });
  }
});

io.on('connection', (socket) => {
  const sessionId = socket.handshake.query['session_id'];
  if (!sessionId) return;
  socket.join(sessionId);
});

server.listen(PORT, () => {
  console.log(`listening on *:${PORT}`);
});
