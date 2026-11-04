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
exports.ProfilesController = void 0;
const common_1 = require("@nestjs/common");
const jwt_auth_guard_1 = require("./common/jwt-auth.guard");
const ownership_1 = require("./common/ownership");
const db_1 = require("./common/db");
let ProfilesController = class ProfilesController {
    async getProfile(req, userId) {
        const { rows } = await db_1.pool.query('SELECT * FROM profile_summary WHERE user_id = $1', [userId]);
        (0, ownership_1.checkOwnership)(req, 'profile', userId, rows[0]?.user_id);
        return rows[0];
    }
    async listCoupons(req, userId) {
        const profile = await db_1.pool.query('SELECT user_id FROM profiles WHERE user_id = $1', [userId]);
        (0, ownership_1.checkOwnership)(req, 'profile', userId, profile.rows[0]?.user_id);
        const { rows } = await db_1.pool.query(`SELECT id, name, discount_type, discount_value, min_order_amount, expires_at, used_at
         FROM coupons WHERE user_id = $1 ORDER BY id`, [userId]);
        return rows;
    }
};
exports.ProfilesController = ProfilesController;
__decorate([
    (0, common_1.Get)(':userId'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('userId', common_1.ParseIntPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number]),
    __metadata("design:returntype", Promise)
], ProfilesController.prototype, "getProfile", null);
__decorate([
    (0, common_1.Get)(':userId/coupons'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Param)('userId', common_1.ParseIntPipe)),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Number]),
    __metadata("design:returntype", Promise)
], ProfilesController.prototype, "listCoupons", null);
exports.ProfilesController = ProfilesController = __decorate([
    (0, common_1.Controller)('profiles'),
    (0, common_1.UseGuards)(jwt_auth_guard_1.JwtAuthGuard)
], ProfilesController);
//# sourceMappingURL=profiles.controller.js.map