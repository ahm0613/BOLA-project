import { Injectable, UnauthorizedException } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import * as fs from 'fs';
import * as jwt from 'jsonwebtoken';
import * as bcrypt from 'bcryptjs';
import { pool } from '../common/db';

const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');

@Injectable()
export class AuthService {
  private readonly privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH!, 'utf8');

  async login(username: string, password: string) {
    const { rows } = await pool.query(
      'SELECT id, password_hash, role FROM users WHERE username = $1',
      [username],
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      throw new UnauthorizedException('invalid credentials');
    }
    return this.issueTokens(user.id, user.role);
  }

  // Refresh Token Rotation: 사용한 토큰은 즉시 폐기하고 새로 발급
  async refresh(refreshToken: string) {
    const { rows } = await pool.query(
      `UPDATE refresh_tokens SET revoked_at = now()
        WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
        RETURNING user_id`,
      [sha256(refreshToken)],
    );
    if (!rows[0]) throw new UnauthorizedException('invalid refresh token');

    const user = await pool.query('SELECT role FROM users WHERE id = $1', [rows[0].user_id]);
    return this.issueTokens(rows[0].user_id, user.rows[0].role);
  }

  async logout(refreshToken: string) {
    await pool.query(
      'UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL',
      [sha256(refreshToken)],
    );
  }

  private async issueTokens(userId: number, role: string) {
    const accessToken = jwt.sign({ role }, this.privateKey, {
      algorithm: 'RS256',
      subject: String(userId),   // sub: 사용자 식별 (Kong, API 서버, 탐지 엔진)
      issuer: 'bola-auth',       // iss: Kong jwt 플러그인이 공개키를 찾는 키
      expiresIn: '15m',
    });
    const refreshToken = randomBytes(32).toString('base64url');
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '7 days')`,
      [userId, sha256(refreshToken)],
    );
    return { userId, accessToken, refreshToken, expiresIn: 900 };
  }
}
