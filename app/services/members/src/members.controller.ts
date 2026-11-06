import { Body, Controller, Get, Param, ParseIntPipe, Patch, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './common/jwt-auth.guard';
import { checkOwnership } from './common/ownership';
import { pool } from './common/db';

@Controller('members')
@UseGuards(JwtAuthGuard)
export class MembersController {
  @Get(':userId')
  async getMember(@Req() req: any, @Param('userId', ParseIntPipe) userId: number) {
    const { rows } = await pool.query(
      `SELECT m.user_id, u.username, m.name, m.phone, m.email, m.birth_date
         FROM member_info m JOIN users u ON u.id = m.user_id
        WHERE m.user_id = $1`,
      [userId],
    );
    checkOwnership(req, 'member', userId, rows[0]?.user_id);
    return rows[0];
  }

  @Patch(':userId')
  async updateMember(
    @Req() req: any,
    @Param('userId', ParseIntPipe) userId: number,
    @Body() body: { phone?: string; email?: string },
  ) {
    const { rows } = await pool.query('SELECT user_id FROM member_info WHERE user_id = $1', [userId]);
    checkOwnership(req, 'member', userId, rows[0]?.user_id);

    const updated = await pool.query(
      `UPDATE member_info
          SET phone = COALESCE($2, phone), email = COALESCE($3, email), updated_at = now()
        WHERE user_id = $1
        RETURNING user_id, name, phone, email`,
      [userId, body.phone, body.email],
    );
    return updated.rows[0];
  }

  @Get(':userId/addresses')
  async listAddresses(@Req() req: any, @Param('userId', ParseIntPipe) userId: number) {
    const member = await pool.query('SELECT user_id FROM member_info WHERE user_id = $1', [userId]);
    checkOwnership(req, 'member', userId, member.rows[0]?.user_id);

    const { rows } = await pool.query('SELECT * FROM addresses WHERE user_id = $1 ORDER BY id', [userId]);
    return rows;
  }

  @Get(':userId/addresses/:addressId')
  async getAddress(
    @Req() req: any,
    @Param('userId', ParseIntPipe) userId: number,
    @Param('addressId', ParseIntPipe) addressId: number,
  ) {
    const { rows } = await pool.query(
      'SELECT * FROM addresses WHERE id = $1 AND user_id = $2',
      [addressId, userId],
    );
    checkOwnership(req, 'address', addressId, rows[0]?.user_id);
    return rows[0];
  }
}
