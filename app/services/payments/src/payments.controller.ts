import { Controller, Get, Param, ParseIntPipe, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './common/jwt-auth.guard';
import { checkOwnership } from './common/ownership';
import { pool } from './common/db';

@Controller('payments')
@UseGuards(JwtAuthGuard)
export class PaymentsController {
  @Get()
  async listMine(@Req() req: any) {
    const { rows } = await pool.query(
      `SELECT id, order_id, method, amount, points_used, status, paid_at
         FROM payments WHERE user_id = $1 ORDER BY id DESC`,
      [req.user.id],
    );
    return rows;
  }

  @Get(':id')
  async getPayment(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query(
      `SELECT p.*, o.order_number
         FROM payments p JOIN orders o ON o.id = p.order_id
        WHERE p.id = $1`,
      [id],
    );
    checkOwnership(req, 'payment', id, rows[0]?.user_id);
    return rows[0];
  }
}
