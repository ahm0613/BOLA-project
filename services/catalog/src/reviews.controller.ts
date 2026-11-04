import {
  BadRequestException, Body, ConflictException, Controller, Delete, ForbiddenException, Get, HttpCode,
  Param, ParseIntPipe, Patch, Post, Req, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from './common/jwt-auth.guard';
import { checkOwnership } from './common/ownership';
import { pool } from './common/db';

function validRating(rating: unknown) {
  return Number.isInteger(rating) && (rating as number) >= 1 && (rating as number) <= 5;
}

function validContent(content: unknown) {
  return typeof content === 'string' && content.trim().length >= 5 && content.length <= 1000;
}

// 리뷰 작성 · 수정 · 삭제 (로그인 필요)
@Controller('reviews')
@UseGuards(JwtAuthGuard)
export class ReviewsController {
  // 내가 쓴 리뷰
  @Get('me')
  async listMine(@Req() req: any) {
    const { rows } = await pool.query(
      `SELECT r.id, r.product_id, p.name AS product_name, p.image, r.order_id, r.rating, r.content,
              r.created_at, r.updated_at
         FROM reviews r JOIN products p ON p.id = r.product_id
        WHERE r.user_id = $1
        ORDER BY r.created_at DESC`,
      [req.user.id],
    );
    return rows;
  }

  // 리뷰를 쓸 수 있는 상품 (배송 완료 + 아직 리뷰 안 씀)
  @Get('writable')
  async writable(@Req() req: any) {
    const { rows } = await pool.query(
      `SELECT DISTINCT o.id AS order_id, o.order_number, oi.product_id, p.name AS product_name, p.image
         FROM orders o
         JOIN order_items oi ON oi.order_id = o.id
         JOIN products p ON p.id = oi.product_id
        WHERE o.user_id = $1 AND o.status = 'delivered'
          AND NOT EXISTS (SELECT 1 FROM reviews r WHERE r.order_id = o.id AND r.product_id = oi.product_id)
        ORDER BY o.id DESC`,
      [req.user.id],
    );
    return rows;
  }

  @Get(':id')
  async get(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query(
      `SELECT r.*, p.name AS product_name, p.image
         FROM reviews r JOIN products p ON p.id = r.product_id WHERE r.id = $1`,
      [id],
    );
    checkOwnership(req, 'review', id, rows[0]?.user_id);
    return rows[0];
  }

  @Post()
  async create(
    @Req() req: any,
    @Body() body: { orderId: number; productId: number; rating: number; content: string },
  ) {
    if (!validRating(body.rating)) throw new BadRequestException('rating must be 1~5');
    if (!validContent(body.content)) throw new BadRequestException('content must be 5~1000 characters');

    const { rows } = await pool.query(
      `SELECT o.user_id, o.status FROM orders o
         JOIN order_items oi ON oi.order_id = o.id
        WHERE o.id = $1 AND oi.product_id = $2`,
      [body.orderId, body.productId],
    );
    if (!rows[0] || rows[0].user_id !== req.user.id) throw new ForbiddenException('not your order');
    if (rows[0].status !== 'delivered') throw new ConflictException('order is not delivered yet');

    const created = await pool.query(
      `INSERT INTO reviews (product_id, user_id, order_id, rating, content)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (order_id, product_id) DO NOTHING
       RETURNING id, product_id, order_id, rating, content, created_at`,
      [body.productId, req.user.id, body.orderId, body.rating, body.content.trim()],
    );
    if (!created.rows[0]) throw new ConflictException('review already written');
    req.bola = { resourceType: 'review', resourceId: created.rows[0].id, ownerId: req.user.id };
    return created.rows[0];
  }

  @Patch(':id')
  async update(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
    @Body() body: { rating?: number; content?: string },
  ) {
    if (body.rating !== undefined && !validRating(body.rating)) throw new BadRequestException('rating must be 1~5');
    if (body.content !== undefined && !validContent(body.content)) {
      throw new BadRequestException('content must be 5~1000 characters');
    }
    const { rows } = await pool.query('SELECT user_id FROM reviews WHERE id = $1', [id]);
    checkOwnership(req, 'review', id, rows[0]?.user_id);

    const updated = await pool.query(
      `UPDATE reviews SET rating = COALESCE($2, rating), content = COALESCE($3, content), updated_at = now()
        WHERE id = $1 RETURNING id, product_id, rating, content, updated_at`,
      [id, body.rating ?? null, body.content?.trim() ?? null],
    );
    return updated.rows[0];
  }

  @Delete(':id')
  @HttpCode(204)
  async remove(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query('SELECT user_id FROM reviews WHERE id = $1', [id]);
    checkOwnership(req, 'review', id, rows[0]?.user_id);
    await pool.query('DELETE FROM reviews WHERE id = $1', [id]);
  }
}
