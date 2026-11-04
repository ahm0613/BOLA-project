import { CanActivate, ExecutionContext } from '@nestjs/common';
export declare class JwtAuthGuard implements CanActivate {
    private readonly publicKey;
    canActivate(ctx: ExecutionContext): boolean;
}
