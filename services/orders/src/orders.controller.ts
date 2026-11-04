import {
  BadRequestException, Body, ConflictException, Controller, Get, HttpCode, Param, ParseIntPipe, Patch, Post, Req,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from './common/jwt-auth.guard';
import { checkOwnership } from './common/ownership';
import { pool } from './common/db';

const FREE_SHIPPING_FROM = 50000;
const SHIPPING_FEE = 3000;
const CARD_COMPANIES = ['신한카드', '현대카드', '국민카드', '삼성카드'];
const BANKS = ['국민은행', '우리은행', '하나은행', '신한은행'];
const pick = <T>(a: T[]) => a[Math.floor(Math.random() * a.length)];
const digits = (n: number) => String(Math.floor(Math.random() * 10 ** n)).padStart(n, '0');

interface CheckoutBody {
  cartItemIds: number[];
  addressId: number;
  couponId?: number;
  pointsUsed?: number;
  method: 'card' | 'bank_transfer' | 'virtual_account';
  memo?: string;
}

@Controller('orders')
@UseGuards(JwtAuthGuard)
export class OrdersController {
  @Get()
  async listMine(@Req() req: any) {
    const { rows } = await pool.query(
      `SELECT o.id, o.order_number, o.status, o.final_amount, o.created_at,
              first.product_name AS first_item, first.image, cnt.item_count
         FROM orders o
         LEFT JOIN LATERAL (SELECT oi.product_name, p.image FROM order_items oi
                              LEFT JOIN products p ON p.id = oi.product_id
                             WHERE oi.order_id = o.id ORDER BY oi.id LIMIT 1) first ON true
         LEFT JOIN LATERAL (SELECT count(*)::int AS item_count FROM order_items WHERE order_id = o.id) cnt ON true
        WHERE o.user_id = $1 ORDER BY o.id DESC`,
      [req.user.id],
    );
    return rows;
  }

  // 장바구니 → 주문 + 결제 (쿠폰·적립금 적용, 재고 차감, 장바구니 비우기)
  @Post()
  async checkout(@Req() req: any, @Body() body: CheckoutBody) {
    const me = req.user.id;
    const ids = Array.isArray(body.cartItemIds) ? body.cartItemIds.filter(Number.isInteger) : [];
    if (ids.length === 0) throw new BadRequestException('select items to order');
    if (!['card', 'bank_transfer', 'virtual_account'].includes(body.method)) {
      throw new BadRequestException('invalid payment method');
    }
    const pointsUsed = Number.isInteger(body.pointsUsed) && body.pointsUsed! > 0 ? body.pointsUsed! : 0;

    const db = await pool.connect();
    try {
      await db.query('BEGIN');

      const items = await db.query(
        `SELECT ci.id, ci.quantity, p.id AS product_id, p.name, p.stock, COALESCE(p.sale_price, p.price) AS price
           FROM cart_items ci JOIN products p ON p.id = ci.product_id
          WHERE ci.id = ANY($1) AND ci.user_id = $2
          FOR UPDATE OF ci, p`,
        [ids, me],
      );
      if (items.rows.length !== ids.length) throw new BadRequestException('invalid cart items');
      const soldOut = items.rows.find((it) => it.stock < it.quantity);
      if (soldOut) throw new ConflictException(`'${soldOut.name}' is out of stock`);

      const addr = await db.query('SELECT * FROM addresses WHERE id = $1 AND user_id = $2', [body.addressId, me]);
      if (!addr.rows[0]) throw new BadRequestException('invalid address');
      const a = addr.rows[0];

      const total = items.rows.reduce((sum, it) => sum + it.price * it.quantity, 0);
      const shipping = total >= FREE_SHIPPING_FROM ? 0 : SHIPPING_FEE;

      let discount = 0;
      if (body.couponId) {
        const c = await db.query(
          `SELECT * FROM coupons WHERE id = $1 AND user_id = $2 AND used_at IS NULL AND expires_at > now()
            FOR UPDATE`,
          [body.couponId, me],
        );
        if (!c.rows[0]) throw new BadRequestException('invalid coupon');
        if (total < c.rows[0].min_order_amount) throw new BadRequestException('order amount is below coupon minimum');
        discount = c.rows[0].discount_type === 'percent'
          ? Math.floor((total * c.rows[0].discount_value) / 100)
          : Math.min(c.rows[0].discount_value, total);
        await db.query('UPDATE coupons SET used_at = now() WHERE id = $1', [body.couponId]);
      }

      const finalAmount = total - discount + shipping;
      if (pointsUsed > 0) {
        if (pointsUsed > finalAmount) throw new BadRequestException('points exceed order amount');
        const p = await db.query(
          'UPDATE profiles SET points = points - $2, updated_at = now() WHERE user_id = $1 AND points >= $2',
          [me, pointsUsed],
        );
        if (p.rowCount === 0) throw new BadRequestException('not enough points');
      }

      const { rows: [{ id }] } = await db.query(`SELECT nextval(pg_get_serial_sequence('orders', 'id')) AS id`);
      const orderNumber = `ORD-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${String(id).padStart(6, '0')}`;
      await db.query(
        `INSERT INTO orders (id, order_number, user_id, status, total_amount, discount_amount, shipping_fee,
                             final_amount, coupon_id, recipient_name, recipient_phone, zipcode, address1, address2,
                             delivery_memo)
         VALUES ($1, $2, $3, 'paid', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [id, orderNumber, me, total, discount, shipping, finalAmount, body.couponId ?? null,
         a.recipient_name, a.recipient_phone, a.zipcode, a.address1, a.address2, body.memo?.slice(0, 200) ?? null],
      );

      for (const it of items.rows) {
        await db.query(
          'INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity) VALUES ($1, $2, $3, $4, $5)',
          [id, it.product_id, it.name, it.price, it.quantity],
        );
        await db.query('UPDATE products SET stock = stock - $2 WHERE id = $1', [it.product_id, it.quantity]);
      }

      // 실제 PG 연동 대신 결제 완료로 기록 (카드번호·계좌는 가짜 마스킹 값)
      const amount = finalAmount - pointsUsed;
      const method = amount === 0 ? 'points' : body.method;
      await db.query(
        `INSERT INTO payments (order_id, user_id, method, amount, points_used, status, transaction_id,
                               card_company, card_number_masked, bank_name, account_masked, paid_at)
         VALUES ($1, $2, $3, $4, $5, 'paid', $6, $7, $8, $9, $10, now())`,
        [id, me, method, amount, pointsUsed, `TX-${Date.now().toString(36).toUpperCase()}-${digits(4)}`,
         method === 'card' ? pick(CARD_COMPANIES) : null,
         method === 'card' ? `${digits(4)}-****-****-${digits(4)}` : null,
         method === 'bank_transfer' || method === 'virtual_account' ? pick(BANKS) : null,
         method === 'bank_transfer' || method === 'virtual_account' ? `${digits(3)}-***-${digits(6)}` : null],
      );

      await db.query('DELETE FROM cart_items WHERE id = ANY($1)', [ids]);
      await db.query('COMMIT');

      req.bola = { resourceType: 'order', resourceId: Number(id), ownerId: me };
      return { id: Number(id), order_number: orderNumber, final_amount: finalAmount, paid_amount: amount };
    } catch (err) {
      await db.query('ROLLBACK');
      throw err;
    } finally {
      db.release();
    }
  }

  @Get(':id')
  async getOrder(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [id]);
    checkOwnership(req, 'order', id, rows[0]?.user_id);

    const items = await pool.query(
      `SELECT oi.product_id, oi.product_name, oi.unit_price, oi.quantity, p.image, p.brand
         FROM order_items oi LEFT JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = $1 ORDER BY oi.id`,
      [id],
    );
    return { ...rows[0], items: items.rows };
  }

  @Post(':id/cancel')
  @HttpCode(200)
  async cancel(@Req() req: any, @Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query('SELECT user_id, status FROM orders WHERE id = $1', [id]);
    checkOwnership(req, 'order', id, rows[0]?.user_id);

    if (!['pending', 'paid'].includes(rows[0].status)) {
      throw new ConflictException(`cannot cancel order in status '${rows[0].status}'`);
    }
    const updated = await pool.query(
      `UPDATE orders SET status = 'cancelled', updated_at = now()
        WHERE id = $1 RETURNING id, order_number, status`,
      [id],
    );
    return updated.rows[0];
  }

  @Patch(':id/delivery-memo')
  async updateMemo(
    @Req() req: any,
    @Param('id', ParseIntPipe) id: number,
    @Body() body: { memo: string },
  ) {
    const { rows } = await pool.query('SELECT user_id FROM orders WHERE id = $1', [id]);
    checkOwnership(req, 'order', id, rows[0]?.user_id);

    const updated = await pool.query(
      `UPDATE orders SET delivery_memo = $2, updated_at = now()
        WHERE id = $1 RETURNING id, order_number, delivery_memo`,
      [id, body.memo],
    );
    return updated.rows[0];
  }
}
