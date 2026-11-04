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
exports.MembersController = void 0;
const common_1 = require("@nestjs/common");
const jwt_auth_guard_1 = require("./common/jwt-auth.guard");
const ownership_1 = require("./common/ownership");
const db_1 = require("./common/db");
let MembersController = class MembersController {
    async getMember(req, userId) {
        const { rows } = await db_1.pool.query(`SELECT m.user_id, u.username, m.name, m.phone, m.email, m.birth_date
         FROM member_info m JOIN users u ON u.id = m.user_id
        WHERE m.user_id = $1`, [userId]);
        (0, ownership_1.checkOwnership)(req, 'member', userId, rows[0]?.user_id);
        return rows[0];
    }
    async updateMember(req, userId, body) {
        const { rows } = await db_1.pool.query('SELECT user_id FROM member_info WHERE user_id = $1', [userId]);
        (0, ownership_1.checkOwnership)(req, 'member', userId, rows[0]?.user_id);
        const updated = await db_1.pool.query(`UPDATE member_info
          SET phone = COALESCE($2, phone), email = COALESCE($3, email), updated_at = now()
        WHERE user_id = $1
        RETURNING user_id, name, phone, email`, [userId, body.phone, body.email]);
        return updated.rows[0];
    }
    async listAddresses(req, userId) {
        const member = await db_1.pool.query('SELECT user_id FROM member_info WHERE user_id = $1', [userId]);
        (0, ownership_1.checkOwnership)(req, 'member', userId, member.rows[0]?.user_id);
        const { rows } = await db_1.pool.query('SELECT * FROM addresses WHERE user_id = $1 ORDER BY id', [userId]);
        return rows;
    }
    async getAddress(req, userId, addressId) {
        const { rows } = await db_1.pool.query('SELECT * FROM addresses WHERE id = $1 AND user_id = $2', [addressId, userId]);
        (0, ownership_1.checkOwnership)(req, 'address', addressId, rows[0]?.user_id);
        return rows[0];
    }
};
exports.MembersController = MembersController;
__decorate([
    (0, common_1.Get)(':userId'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('userId', common_1.ParseIntPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number]),
    __metadata("design:returntype", Promise)
], MembersController.prototype, "getMember", null);
__decorate([
    (0, common_1.Patch)(':userId'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('userId', common_1.ParseIntPipe)),
    __param(2, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number, Object]),
    __metadata("design:returntype", Promise)
], MembersController.prototype, "updateMember", null);
__decorate([
    (0, common_1.Get)(':userId/addresses'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('userId', common_1.ParseIntPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number]),
    __metadata("design:returntype", Promise)
], MembersController.prototype, "listAddresses", null);
__decorate([
    (0, common_1.Get)(':userId/addresses/:addressId'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('userId', common_1.ParseIntPipe)),
    __param(2, (0, common_1.Param)('addressId', common_1.ParseIntPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number, Number]),
    __metadata("design:returntype", Promise)
], MembersController.prototype, "getAddress", null);
exports.MembersController = MembersController = __decorate([
    (0, common_1.Controller)('members'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard)
], MembersController);
//# sourceMappingURL=members.controller.js.map