import {
  BadRequestException, Body, Controller, Delete, Get, HttpCode, NotFoundException, Param, ParseIntPipe, Patch,
  Post, Req, UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from './common/jwt-auth.guard';
import { checkOwnership } from './common/ownership';
import { pool } from './common/db';

function validQuantity(q: unknown) {
  return Number.isInteger(q) && (q as number) >= 1 && (q as number) <= 99;
}

@Controller('cart')
@UseGuards(JwtAuthGuard)
export class CartController {
  // 내 장바구니 (토큰 기준으로 내 것만)
  @Get()
  async listMine(@Req() req: any) {
    const { rows } = await pool.query(
      `SELECT ci.id, ci.product_id, ci.quantity, p.brand, p.name, p.image, p.price, p.stock,
              COALESCE(p.sale_price, p.price) AS final_price
         FROM cart_items ci JOIN products p ON p.id = ci.product_id
        WHERE ci.user_id = $1
        ORDER BY ci.id DESC`,
      [req.user.id],
    );
    return rows;
  }

  // 같은 상품을 다시 담으면 수량을 더함
  @Post('items')
  async add(@Req() req: any, @Body() body: { productId: number; quantity: number }) {
    if (!validQuantity(body.quantity)) throw new BadRequestException('quantity must be 1~99');
    const product = await pool.query('SELECT id FROM products WHERE id = $1', [body.productId]);
    if (!product.rows[0]) throw new NotFoundException('product not found');

    const { rows } = await pool.query(
      `INSERT INTO cart_items (user_id, product_id, quantity) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, product_id)
       DO UPDATE SET quantity = LEAST(cart_items.quantity + EXCLUDED.quantity, 99)
       RETURNING id, product_id, quantity`,
      [req.user.id, body.productId, body.quantity],
    );
    req.bola = { resourceType: 'cart_item', resourceId: rows[0].id, ownerId: req.user.id };
    return rows[0];
  }

  @Patch('items/:id')
  async update(@Req() req: any, @Param('id', ParseIntPipe) id: number, @Body() body: { quantity: number }) {
    if (!validQuantity(body.quantity)) throw new BadRequestException('quantity must be 1~99');
    const { rows } = await pool.query('SELECT user_id FROM cart_items WHERE id = $1', [id]);
    checkOwnership(req, 'cart_item', id, rows[0]?.user_id);

    const updated = await pool.query(
      'UPDATE cart_items SET quantity = $2 WHERE id = $1 RETURNING id, product_id, quantity',
      [id, body.quantity],
    );
    return updated.rows[0];
  }

  @Delete('items/:id')
  @HttpCode(204)
  async remove(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query('SELECT user_id FROM cart_items WHERE id = $1', [id]);
    checkOwnership(req, 'cart_item', id, rows[0]?.user_id);
    await pool.query('DELETE FROM cart_items WHERE id = $1', [id]);
  }
}
