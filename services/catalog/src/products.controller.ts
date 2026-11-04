import { Controller, Get, NotFoundException, Param, ParseIntPipe, Query } from '@nestjs/common';
import { pool } from './common/db';

// 상품 · 카테고리 · 상품 리뷰 목록: 로그인 없이 보는 공개 API (Kong에서 JWT 검사 안 함)

const PRODUCT_COLUMNS = `
  p.id, p.category_id, c.name AS category_name, p.brand, p.name, p.price, p.sale_price,
  COALESCE(p.sale_price, p.price) AS final_price, p.stock, p.image,
  COALESCE(r.avg_rating, 0) AS avg_rating, COALESCE(r.review_count, 0) AS review_count`;

const PRODUCT_FROM = `
  FROM products p
  JOIN categories c ON c.id = p.category_id
  LEFT JOIN (SELECT product_id, round(avg(rating), 1)::float AS avg_rating, count(*)::int AS review_count
               FROM reviews GROUP BY product_id) r ON r.product_id = p.id`;

const SORTS: Record<string, string> = {
  popular: 'review_count DESC, p.id',
  new: 'p.created_at DESC, p.id DESC',
  price_asc: 'final_price ASC, p.id',
  price_desc: 'final_price DESC, p.id',
  rating: 'avg_rating DESC, review_count DESC, p.id',
};

@Controller('categories')
export class CategoriesController {
  @Get()
  async list() {
    const { rows } = await pool.query(
      `SELECT c.id, c.name, count(p.id)::int AS product_count
         FROM categories c LEFT JOIN products p ON p.category_id = c.id
        GROUP BY c.id ORDER BY c.sort_order`,
    );
    return rows;
  }
}

@Controller('products')
export class ProductsController {
  // GET /products?category=1&q=키보드&sort=price_asc&limit=8
  @Get()
  async list(
    @Query('category') category?: string,
    @Query('q') q?: string,
    @Query('sort') sort = 'popular',
    @Query('limit') limit = '60',
  ) {
    const where: string[] = [];
    const params: unknown[] = [];
    if (category && /^\d+$/.test(category)) {
      params.push(Number(category));
      where.push(`p.category_id = $${params.length}`);
    }
    if (q?.trim()) {
      params.push(`%${q.trim()}%`);
      where.push(`(p.name ILIKE $${params.length} OR p.brand ILIKE $${params.length})`);
    }
    params.push(Math.min(Math.max(Number(limit) || 60, 1), 100));

    const { rows } = await pool.query(
      `SELECT ${PRODUCT_COLUMNS} ${PRODUCT_FROM}
        ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
        ORDER BY ${SORTS[sort] ?? SORTS.popular}
        LIMIT $${params.length}`,
      params,
    );
    return rows;
  }

  @Get(':id')
  async get(@Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query(
      `SELECT ${PRODUCT_COLUMNS}, p.description ${PRODUCT_FROM} WHERE p.id = $1`,
      [id],
    );
    if (!rows[0]) throw new NotFoundException('product not found');
    return rows[0];
  }

  // 작성자 아이디는 앞 3글자만 보여줌 (alice → ali**)
  @Get(':id/reviews')
  async reviews(@Param('id', ParseIntPipe) id: number) {
    const { rows } = await pool.query(
      `SELECT r.id, r.rating, r.content, r.created_at,
              left(u.username, 3) || repeat('*', greatest(length(u.username) - 3, 2)) AS writer
         FROM reviews r JOIN users u ON u.id = r.user_id
        WHERE r.product_id = $1
        ORDER BY r.created_at DESC`,
      [id],
    );
    return rows;
  }
}
