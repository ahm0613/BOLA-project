import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import * as fs from 'fs';
import * as jwt from 'jsonwebtoken';

// Kong이 이미 검증했지만, Kong을 우회한 요청에 대비해 한 번 더 검증 (심층 방어)
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH!, 'utf8');

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const token = req.headers.authorization?.replace(/^Bearer /, '');
    if (!token) throw new UnauthorizedException();

    try {
      const payload = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
        issuer: 'bola-auth',
      }) as jwt.JwtPayload;
      req.user = { id: Number(payload.sub), role: payload.role };
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}
