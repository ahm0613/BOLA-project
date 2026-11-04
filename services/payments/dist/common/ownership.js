"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkOwnership = checkOwnership;
const common_1 = require("@nestjs/common");
const VULNERABLE = process.env.BOLA_VULNERABLE === 'true';
function checkOwnership(req, resourceType, resourceId, ownerId) {
    req.bola = { resourceType, resourceId, ownerId: ownerId ?? null };
    if (ownerId === undefined)
        throw new common_1.NotFoundException(`${resourceType} not found`);
    if (VULNERABLE)
        return;
    if (ownerId !== req.user.id && req.user.role !== 'admin') {
        throw new common_1.ForbiddenException(`not your ${resourceType}`);
    }
}
//# sourceMappingURL=ownership.js.map