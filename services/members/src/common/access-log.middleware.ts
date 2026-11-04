import * as fs from 'fs';
import * as path from 'path';

// 요청 1건 = JSON 1줄 → 공유 볼륨 → Wazuh Agent
export function accessLog(service: string) {
  const dir = process.env.LOG_DIR ?? `/logs/${service}`;
  fs.mkdirSync(dir, { recursive: true });
  const stream = fs.createWriteStream(path.join(dir, 'access.json'), { flags: 'a' });

  return (req: any, res: any, next: () => void) => {
    const start = Date.now();
    // Guard나 핸들러가 403을 던져도 finish는 발생하므로 거부된 요청까지 기록됨
    res.on('finish', () => {
      stream.write(JSON.stringify({
        timestamp: new Date().toISOString(),
        service,
        request_id: req.headers['x-request-id'] ?? null,
        user_id: req.user?.id ?? null,
        method: req.method,
        path: req.originalUrl,
        resource_type: req.bola?.resourceType ?? null,
        resource_id: req.bola?.resourceId ?? null,
        owner_id: req.bola?.ownerId ?? null,   // user_id ≠ owner_id → BOLA 신호
        status: res.statusCode,
        latency_ms: Date.now() - start,
        client_ip: req.headers['x-forwarded-for'] ?? req.ip,
      }) + '\n');
    });
    next();
  };
}
