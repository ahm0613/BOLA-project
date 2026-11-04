"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OrdersController = void 0;
const common_1 = require("@nestjs/common");
const jwt_auth_guard_1 = require("./common/jwt-auth.guard");
const ownership_1 = require("./common/ownership");
const db_1 = require("./common/db");
let OrdersController = class OrdersController {
    async listMine(req) {
        const { rows } = await db_1.pool.query(`SELECT id, order_number, status, final_amount, created_at
         FROM orders WHERE user_id = $1 ORDER BY id DESC`, [req.user.id]);
        return rows;
    }
    async getOrder(req, id) {
        const { rows } = await db_1.pool.query('SELECT * FROM orders WHERE id = $1', [id]);
        (0, ownership_1.checkOwnership)(req, 'order', id, rows[0]?.user_id);
        const items = await db_1.pool.query('SELECT product_name, unit_price, quantity FROM order_items WHERE order_id = $1 ORDER BY id', [id]);
        return { ...rows[0], items: items.rows };
    }
    async cancel(req, id) {
        const { rows } = await db_1.pool.query('SELECT user_id, status FROM orders WHERE id = $1', [id]);
        (0, ownership_1.checkOwnership)(req, 'order', id, rows[0]?.user_id);
        if (!['pending', 'paid'].includes(rows[0].status)) {
            throw new common_1.ConflictException(`cannot cancel order in status '${rows[0].status}'`);
        }
        const updated = await db_1.pool.query(`UPDATE orders SET status = 'cancelled', updated_at = now()
        WHERE id = $1 RETURNING id, order_number, status`, [id]);
        return updated.rows[0];
    }
    async updateMemo(req, id, body) {
        const { rows } = await db_1.pool.query('SELECT user_id FROM orders WHERE id = $1', [id]);
        (0, ownership_1.checkOwnership)(req, 'order', id, rows[0]?.user_id);
        const updated = await db_1.pool.query(`UPDATE orders SET delivery_memo = $2, updated_at = now()
        WHERE id = $1 RETURNING id, order_number, delivery_memo`, [id, body.memo]);
        return updated.rows[0];
    }
};
exports.OrdersController = OrdersController;
__decorate([
    (0, common_1.Get)(),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "listMine", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('id', common_1.ParseIntPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "getOrder", null);
__decorate([
    (0, common_1.Post)(':id/cancel'),
    (0, common_1.HttpCode)(200),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('id', common_1.ParseIntPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "cancel", null);
__decorate([
    (0, common_1.Patch)(':id/delivery-memo'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('id', common_1.ParseIntPipe)),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number, Object]),
    __metadata("design:returntype", Promise)
], OrdersController.prototype, "updateMemo", null);
exports.OrdersController = OrdersController = __decorate([
    (0, common_1.Controller)('orders'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard)
], OrdersController);
//# sourceMappingURL=orders.controller.js.map