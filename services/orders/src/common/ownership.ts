import { ForbiddenException, NotFoundException } from '@nestjs/common';

const VULNERABLE = process.env.BOLA_VULNERABLE === 'true';

// 객체 인가 검증 + 로그용 정보 기록
// ownerId가 undefined면 리소스가 없다는 뜻 → 404
export function checkOwnership(req: any, resourceType: string, resourceId: number, ownerId?: number) {
  req.bola = { resourceType, resourceId, ownerId: ownerId ?? null };

  if (ownerId === undefined) throw new NotFoundException(`${resourceType} not found`);
  if (VULNERABLE) return;   // ⚠️ 취약 서버: 소유권 검사 생략

  if (ownerId !== req.user.id && req.user.role !== 'admin') {
    throw new ForbiddenException(`not your ${resourceType}`);
  }
}
