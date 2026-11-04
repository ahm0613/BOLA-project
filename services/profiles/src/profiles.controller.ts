import { Controller, Get, Param, ParseIntPipe, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './common/jwt-auth.guard';
import { checkOwnership } from './common/ownership';
import { pool } from './common/db';

@Controller('profiles')
@UseGuards(JwtAuthGuard)
export class ProfilesController {
  // 이름, 등급, 적립금, 쿠폰 개수, 주문 상태별 개수 (profile_summary VIEW)
  @Get(':userId')
  async getProfile(@Req() req: any, @Param('userId', ParseIntPipe) userId: number) {
    const { rows } = await pool.query('SELECT * FROM profile_summary WHERE user_id = $1', [userId]);
    checkOwnership(req, 'profile', userId, rows[0]?.user_id);
    return rows[0];
  }

  @Get(':userId/coupons')
  async listCoupons(@Req() req: any, @Param('userId', ParseIntPipe) userId: number) {
    const profile = await pool.query('SELECT user_id FROM profiles WHERE user_id = $1', [userId]);
    checkOwnership(req, 'profile', userId, profile.rows[0]?.user_id);

    const { rows } = await pool.query(
      `SELECT id, name, discount_type, discount_value, min_order_amount, expires_at, used_at
         FROM coupons WHERE user_id = $1 ORDER BY id`,
      [userId],
    );
    return rows;
  }
}
